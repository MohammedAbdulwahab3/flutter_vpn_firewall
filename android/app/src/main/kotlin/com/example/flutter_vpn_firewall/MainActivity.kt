package com.example.flutter_vpn_firewall

import android.content.Intent
import android.net.VpnService
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel

class MainActivity: FlutterActivity() {
  private val METHOD_CHANNEL = "vpn.firewall/methods"
  private val EVENT_CHANNEL  = "vpn.firewall/logs"

  companion object {
    // Used by the VPN service to send logs to Flutter
    @JvmStatic var events: EventChannel.EventSink? = null
  }

  override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
    super.configureFlutterEngine(flutterEngine)

    // MethodChannel: start VPN, update domain/app blocklists
    MethodChannel(flutterEngine.dartExecutor.binaryMessenger, METHOD_CHANNEL)
      .setMethodCallHandler { call, result ->
        when (call.method) {
          "startVpn" -> {
            val prepIntent = VpnService.prepare(this)
            if (prepIntent != null) {
              startActivityForResult(prepIntent, 0)
              result.success("permission_requested")
            } else {
              startService(Intent(this, MyVpnService::class.java))
              result.success("vpn_started")
            }
          }
          "setBlocklist" -> {
            @Suppress("UNCHECKED_CAST")
            MyVpnService.blocklist = (call.arguments as List<String>).toMutableList()
            result.success(null)
          }
          "setAppBlocklist" -> {
            @Suppress("UNCHECKED_CAST")
            MyVpnService.disallowedApps = (call.arguments as List<String>).toMutableList()
            result.success(null)
          }
          else -> result.notImplemented()
        }
      }

    // EventChannel: receive log events from the VPN service
    EventChannel(flutterEngine.dartExecutor.binaryMessenger, EVENT_CHANNEL)
      .setStreamHandler(object: EventChannel.StreamHandler {
        override fun onListen(args: Any?, sink: EventChannel.EventSink) {
          events = sink
        }
        override fun onCancel(args: Any?) {
          events = null
        }
      })
  }
}
