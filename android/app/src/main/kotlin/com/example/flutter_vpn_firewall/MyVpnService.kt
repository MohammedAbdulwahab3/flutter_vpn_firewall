package com.example.flutter_vpn_firewall

import android.net.VpnService
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.util.concurrent.Executors
import kotlin.concurrent.thread

class MyVpnService : VpnService() {
    private var vpnInterface: ParcelFileDescriptor? = null

    // Handler on main thread for sending events
    private val mainHandler = Handler(Looper.getMainLooper())

    // Fixed-size pool for network I/O tasks
    private val executor = Executors.newFixedThreadPool(4)

    companion object {
        @JvmStatic var blocklist      = mutableListOf("facebook.com")
        @JvmStatic var disallowedApps = mutableListOf<String>()
    }

    override fun onStartCommand(intent: android.content.Intent?, flags: Int, startId: Int): Int {
        setupVpn()
        return START_STICKY
    }

    private fun setupVpn() {
        val builder = Builder().apply {
            setSession("FlutterVPN")
            addAddress("10.0.0.2", 32)
            addDnsServer("8.8.8.8")
            addRoute("0.0.0.0", 0)
            disallowedApps.forEach { pkg ->
                try { addDisallowedApplication(pkg) } catch (_: Exception) { }
            }
        }
        vpnInterface = builder.establish()

        vpnInterface?.fileDescriptor?.let { fd ->
            thread { vpnLoop(fd) }
        }
    }

    private fun vpnLoop(fd: FileDescriptor) {
        val input  = FileInputStream(fd)
        val output = FileOutputStream(fd)
        val buffer = ByteArray(32767)

        while (true) {
            val len = try {
                input.read(buffer)
            } catch (e: Exception) {
                Log.e("MyVpnService", "VPN read error", e)
                break
            }
            if (len <= 0) continue

            // Parse packet & DNS
            val pkt    = PacketParser.parseIpPacket(buffer, len)
            val dns    = PacketParser.parseDns(pkt)
            val domain = dns?.questions?.firstOrNull()?.name

            // Decide block or allow
            val isBlocked = domain?.let { d ->
                blocklist.any { b -> d.contains(b, ignoreCase = true) }
            } == true

            val action = if (isBlocked) {
                "BLOCKED: $domain"
            } else {
                "ALLOWED: ${pkt.srcAddr} -> ${pkt.dstAddr} [proto=${pkt.protocol}]"
            }

            // Send event on main thread
            mainHandler.post {
                MainActivity.events?.success(action)
            }

            // Forward if allowed (only UDP)
            if (!isBlocked && pkt.protocol == 17) {
                executor.submit {
                    forwardUdp(pkt, output)
                }
            }
            // TODO: TCP forwarding if needed
        }
    }


private fun forwardUdp(pkt: PacketParser.IpPacket, output: FileOutputStream) {
  executor.submit {
    try {
      val udp = PacketParser.parseUdp(pkt) ?: return@submit
      // 1) Send via normal socket to get real response
      DatagramSocket().use { sock ->
        sock.send(DatagramPacket(
          udp.data, udp.data.size,
          InetAddress.getByName(pkt.dstAddr), udp.dstPort
        ))
        val recvBuf = ByteArray(4096)
        val recvPkt = DatagramPacket(recvBuf, recvBuf.size)
        sock.receive(recvPkt)
        val respData = recvPkt.data.copyOf(recvPkt.length)

        // 2) Build UDP header
        val udpPkt = PacketBuilder.buildUdpPacket(
          srcIp = pkt.dstAddr, dstIp = pkt.srcAddr,
          srcPort = udp.dstPort, dstPort = udp.srcPort,
          data = respData
        )
        // 3) Build IP header + UDP payload
        val totalLen = 20 + udpPkt.size
        val ipHdr = PacketBuilder.buildIpHeader(
          src = pkt.dstAddr, dst = pkt.srcAddr,
          totalLength = totalLen, protocol = 17
        )
        // 4) Write back into TUN: IP header + UDP packet
        output.write(ipHdr)
        output.write(udpPkt)
      }
    } catch (e: Exception) {
      Log.e("MyVpnService", "UDP forward error", e)
    }
  }
}



    override fun onDestroy() {
        super.onDestroy()
        executor.shutdownNow()
        vpnInterface?.close()
    }
}
