import 'dart:async';
import 'dart:io';

import 'package:device_info_plus/device_info_plus.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:package_info_plus/package_info_plus.dart';

import '../models/auth_session.dart';
import 'auth_service.dart';

class PushService {
  PushService(this._authService);

  final AuthService _authService;
  StreamSubscription<String>? _tokenRefreshSubscription;
  bool _initialized = false;

  Future<void> initializeAndRegister(AuthSession session) async {
    try {
      if (!_initialized) {
        await Firebase.initializeApp();
        _initialized = true;
      }
    } catch (_) {
      // Firebase config missing in local dev or unsupported platform.
      return;
    }

    try {
      await FirebaseMessaging.instance.requestPermission(
        alert: true,
        badge: true,
        sound: true,
      );
      final token = await FirebaseMessaging.instance.getToken();
      if (token != null && token.isNotEmpty) {
        await _registerToken(session, token);
      }
      _tokenRefreshSubscription?.cancel();
      _tokenRefreshSubscription = FirebaseMessaging.instance.onTokenRefresh.listen(
        (nextToken) async {
          if (nextToken.isNotEmpty) {
            await _registerToken(session, nextToken);
          }
        },
      );
    } catch (_) {
      // Push registration is best-effort.
      return;
    }
  }

  Future<void> dispose() async {
    await _tokenRefreshSubscription?.cancel();
  }

  Future<void> _registerToken(AuthSession session, String pushToken) async {
    final deviceInfoPlugin = DeviceInfoPlugin();
    final packageInfo = await PackageInfo.fromPlatform();
    final locale = Platform.localeName;
    final timezone = DateTime.now().timeZoneName;

    String platform = 'android';
    String deviceId = 'unknown-device';
    if (Platform.isIOS) {
      platform = 'ios';
      final iosInfo = await deviceInfoPlugin.iosInfo;
      deviceId = iosInfo.identifierForVendor ?? iosInfo.utsname.machine;
    } else if (Platform.isAndroid) {
      platform = 'android';
      final androidInfo = await deviceInfoPlugin.androidInfo;
      deviceId = androidInfo.id;
    }

    await _authService.registerDevice(
      accessToken: session.accessToken,
      platform: platform,
      deviceId: deviceId,
      pushToken: pushToken,
      appVersion: packageInfo.version,
      locale: locale,
      timezone: timezone,
    );
  }
}
