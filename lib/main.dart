import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

void main() => runApp(VpnApp());

class VpnApp extends StatefulWidget {
  const VpnApp({super.key});

  @override
  State<VpnApp> createState() => _VpnAppState();
}

class _VpnAppState extends State<VpnApp> {
  static const _methods = MethodChannel('vpn.firewall/methods');
  static const _events = EventChannel('vpn.firewall/logs');

  final List<String> _logs = [];
  final _domainCtrl = TextEditingController();
  final _appCtrl = TextEditingController();
  final List<String> _domains = ['facebook.com'];
  final List<String> _apps = [];

  StreamSubscription? _sub;

  @override
  void initState() {
    super.initState();
    _sub = _events.receiveBroadcastStream().listen((dynamic event) {
      setState(() => _logs.insert(0, event as String));
    });
  }

  @override
  void dispose() {
    _sub?.cancel();
    super.dispose();
  }

  Future<void> _startVpn() async {
    await _methods.invokeMethod('setBlocklist', _domains);
    await _methods.invokeMethod('setAppBlocklist', _apps);
    await _methods.invokeMethod('startVpn');
  }

  void _addDomain() {
    final d = _domainCtrl.text.trim();
    if (d.isNotEmpty && !_domains.contains(d)) {
      setState(() => _domains.add(d));
    }
    _domainCtrl.clear();
  }

  void _addApp() {
    final a = _appCtrl.text.trim();
    if (a.isNotEmpty && !_apps.contains(a)) {
      setState(() => _apps.add(a));
    }
    _appCtrl.clear();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(title: Text('VPN Firewall')),
        body: Column(
          children: [
            Padding(
              padding: EdgeInsets.all(8),
              child: Row(
                children: [
                  Expanded(
                    child: TextField(
                      controller: _domainCtrl,
                      decoration: InputDecoration(labelText: 'Block domain'),
                    ),
                  ),
                  ElevatedButton(onPressed: _addDomain, child: Text('Add')),
                ],
              ),
            ),
            Padding(
              padding: EdgeInsets.all(8),
              child: Row(
                children: [
                  Expanded(
                    child: TextField(
                      controller: _appCtrl,
                      decoration: InputDecoration(labelText: 'Block app pkg'),
                    ),
                  ),
                  ElevatedButton(onPressed: _addApp, child: Text('Add')),
                ],
              ),
            ),
            ElevatedButton(onPressed: _startVpn, child: Text('Start VPN')),
            Divider(),
            Expanded(
              child: ListView.builder(
                reverse: true,
                itemCount: _logs.length,
                itemBuilder:
                    (_, i) => ListTile(
                      title: Text(_logs[i], style: TextStyle(fontSize: 12)),
                    ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
