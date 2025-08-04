package com.example.flutter_vpn_firewall

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets

object PacketParser {
  private const val DEFAULT_IHL = 20  // Minimum IPv4 header size

  data class IpPacket(
    val protocol:  Int,
    val srcAddr:   String,
    val dstAddr:   String,
    val headerLen: Int,
    val payload:   ByteArray
  )
  data class UdpSegment(val srcPort: Int, val dstPort: Int, val data: ByteArray)
  data class DnsQuestion(val name: String)
  data class DnsPacket(val questions: List<DnsQuestion>)

  fun parseIpPacket(buf: ByteArray, length: Int): IpPacket {
    val ihl      = (buf[0].toInt() and 0x0F) * 4
    val protocol = buf[9].toInt() and 0xFF
    val src      = buf.slice(12..15).joinToString(".") { (it.toInt() and 0xFF).toString() }
    val dst      = buf.slice(16..19).joinToString(".") { (it.toInt() and 0xFF).toString() }
    val payload  = buf.copyOfRange(ihl, length)
    return IpPacket(protocol, src, dst, ihl, payload)
  }

  fun parseUdp(ip: IpPacket): UdpSegment? {
    if (ip.protocol != 17 || ip.payload.size < 8) return null
    val bb      = ByteBuffer.wrap(ip.payload)
    val srcPort = bb.short.toInt() and 0xFFFF
    val dstPort = bb.short.toInt() and 0xFFFF
    val data    = ip.payload.copyOfRange(8, ip.payload.size)
    return UdpSegment(srcPort, dstPort, data)
  }

  fun parseDns(ip: IpPacket): DnsPacket? {
    val udp = parseUdp(ip) ?: return null
    if (udp.dstPort != 53) return null

    // Skip DNS header (12 bytes) and read one QNAME
    val data = udp.data
    var idx  = 12
    val labels = mutableListOf<String>()
    while (idx < data.size && data[idx].toInt() != 0) {
      val len = data[idx].toInt() and 0xFF
      idx++
      labels.add(String(data, idx, len, StandardCharsets.ISO_8859_1))
      idx += len
    }
    val name = labels.joinToString(".")
    return DnsPacket(listOf(DnsQuestion(name)))
  }

  fun buildIpPacket(srcIp: String, dstIp: String, payload: ByteArray): ByteArray {
    // Stub: just prepend a zeroed header
    val packet = ByteArray(DEFAULT_IHL + payload.size)
    System.arraycopy(payload, 0, packet, DEFAULT_IHL, payload.size)
    return packet
  }
}
