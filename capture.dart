// Capture dart:io's real TLS fingerprint — the thing the Dart relay (and the
// Flutter app's dart:io) produce. Hits a JA3/JA4 echo and prints what it saw.
// Run: scratch/dart-sdk/bin/dart.exe scratch/bun-tls/capture.dart
// Uses the SAME HttpClient the relay uses, so the ClientHello == the relay's.
import 'dart:convert';
import 'dart:io';

Future<String> get(String url) async {
  final c = HttpClient()..userAgent = 'Dart/3.10 (dart:io)';
  try {
    final req = await c.getUrl(Uri.parse(url));
    final res = await req.close();
    return await res.transform(utf8.decoder).join();
  } finally {
    c.close(force: true);
  }
}

void main() async {
  // Two independent echoes to cross-check.
  for (final url in ['https://tls.peet.ws/api/all', 'https://check.ja3.zone/']) {
    try {
      final body = await get(url);
      final j = jsonDecode(body);
      final tls = j['tls'] ?? j;
      print('=== $url ===');
      print('ja3      : ${tls['ja3'] ?? j['ja3']}');
      print('ja3_hash : ${tls['ja3_hash'] ?? j['ja3_hash'] ?? j['hash']}');
      print('ja4      : ${tls['ja4'] ?? j['ja4']}');
      print('ja4_r    : ${tls['ja4_r'] ?? j['ja4_r']}');
      print('alpn     : ${(tls['extensions'] is List ? '' : '')}${j['akamai_text'] ?? ''}');
      print('');
    } catch (e) {
      print('=== $url === ERROR: $e\n');
    }
  }
}
