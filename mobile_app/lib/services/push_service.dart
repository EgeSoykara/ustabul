import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:device_info_plus/device_info_plus.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';
import 'package:package_info_plus/package_info_plus.dart';

import '../models/auth_session.dart';
import 'auth_service.dart';

const AndroidNotificationChannel _defaultNotificationChannel =
    AndroidNotificationChannel(
  'ustabul_general',
  'UstaBul Bildirimleri',
  description: 'Mesajlar, talepler ve randevular için UstaBul bildirimleri.',
  importance: Importance.high,
);

@pragma('vm:entry-point')
Future<void> firebaseMessagingBackgroundHandler(RemoteMessage message) async {
  try {
    await Firebase.initializeApp();
  } catch (_) {
    return;
  }

  final localNotifications = FlutterLocalNotificationsPlugin();
  await _initializeLocalNotificationsPlugin(localNotifications);

  final title = message.notification?.title ??
      PushService.buildFallbackTitle(message.data);
  final body =
      message.notification?.body ?? PushService.buildFallbackBody(message.data);
  if (title.isEmpty && body.isEmpty) {
    return;
  }

  await localNotifications.show(
    message.messageId.hashCode ^ title.hashCode ^ body.hashCode,
    title,
    body,
    _notificationDetails(),
    payload: jsonEncode(message.data),
  );
}

Future<void> _initializeLocalNotificationsPlugin(
  FlutterLocalNotificationsPlugin localNotifications,
) async {
  const androidSettings = AndroidInitializationSettings('@mipmap/ic_launcher');
  const iosSettings = DarwinInitializationSettings();
  await localNotifications.initialize(
    const InitializationSettings(
      android: androidSettings,
      iOS: iosSettings,
    ),
  );

  final androidPlugin =
      localNotifications.resolvePlatformSpecificImplementation<
          AndroidFlutterLocalNotificationsPlugin>();
  await androidPlugin?.createNotificationChannel(_defaultNotificationChannel);
}

NotificationDetails _notificationDetails() {
  return NotificationDetails(
    android: AndroidNotificationDetails(
      _defaultNotificationChannel.id,
      _defaultNotificationChannel.name,
      channelDescription: _defaultNotificationChannel.description,
      importance: Importance.high,
      priority: Priority.high,
      playSound: true,
    ),
    iOS: const DarwinNotificationDetails(
      presentAlert: true,
      presentBadge: true,
      presentSound: true,
    ),
  );
}

class PushRegistration {
  const PushRegistration({
    required this.platform,
    required this.deviceId,
    required this.pushToken,
    required this.appVersion,
    required this.locale,
    required this.timezone,
  });

  final String platform;
  final String deviceId;
  final String pushToken;
  final String appVersion;
  final String locale;
  final String timezone;

  Map<String, dynamic> toJson() {
    return {
      'platform': platform,
      'device_id': deviceId,
      'push_token': pushToken,
      'app_version': appVersion,
      'locale': locale,
      'timezone': timezone,
    };
  }
}

class PushService {
  PushService([this._authService]);

  static bool _backgroundHandlerRegistered = false;

  final AuthService? _authService;
  final FlutterLocalNotificationsPlugin _localNotifications =
      FlutterLocalNotificationsPlugin();
  StreamSubscription<String>? _tokenRefreshSubscription;
  StreamSubscription<RemoteMessage>? _foregroundMessageSubscription;
  bool _initialized = false;
  bool _localNotificationsReady = false;
  PushRegistration? _lastRegistration;

  static void registerBackgroundHandler() {
    if (_backgroundHandlerRegistered) {
      return;
    }
    FirebaseMessaging.onBackgroundMessage(firebaseMessagingBackgroundHandler);
    _backgroundHandlerRegistered = true;
  }

  Future<void> initializeAndRegister(AuthSession session) async {
    await initialize(
      onRegistrationChanged: (registration) async {
        await _registerToken(session, registration);
      },
    );
  }

  Future<PushRegistration?> initialize({
    Future<void> Function(PushRegistration registration)? onRegistrationChanged,
  }) async {
    registerBackgroundHandler();

    try {
      if (!_initialized) {
        await Firebase.initializeApp();
        _initialized = true;
      }
    } catch (_) {
      // Firebase config missing in local dev or unsupported platform.
      return null;
    }

    try {
      await _initializeLocalNotifications();
      await _requestLocalNotificationPermissions();
      await FirebaseMessaging.instance.requestPermission(
        alert: true,
        badge: true,
        sound: true,
      );
      await FirebaseMessaging.instance
          .setForegroundNotificationPresentationOptions(
        alert: true,
        badge: true,
        sound: true,
      );

      final token = await FirebaseMessaging.instance.getToken();
      if (token != null && token.isNotEmpty) {
        final registration = await _buildRegistration(token);
        if (registration != null) {
          _lastRegistration = registration;
          if (onRegistrationChanged != null) {
            await onRegistrationChanged(registration);
          }
        }
      }

      _tokenRefreshSubscription?.cancel();
      _tokenRefreshSubscription =
          FirebaseMessaging.instance.onTokenRefresh.listen(
        (nextToken) async {
          if (nextToken.isEmpty) {
            return;
          }
          final registration = await _buildRegistration(nextToken);
          if (registration == null) {
            return;
          }
          _lastRegistration = registration;
          if (onRegistrationChanged != null) {
            await onRegistrationChanged(registration);
          }
        },
      );

      _foregroundMessageSubscription?.cancel();
      _foregroundMessageSubscription =
          FirebaseMessaging.onMessage.listen(_showForegroundNotification);
    } catch (_) {
      // Push registration is best-effort.
      return _lastRegistration;
    }

    return _lastRegistration;
  }

  Future<void> dispose() async {
    await _tokenRefreshSubscription?.cancel();
    await _foregroundMessageSubscription?.cancel();
  }

  Future<void> _initializeLocalNotifications() async {
    if (_localNotificationsReady) {
      return;
    }

    await _initializeLocalNotificationsPlugin(_localNotifications);
    _localNotificationsReady = true;
  }

  Future<void> _requestLocalNotificationPermissions() async {
    final androidPlugin =
        _localNotifications.resolvePlatformSpecificImplementation<
            AndroidFlutterLocalNotificationsPlugin>();
    await androidPlugin?.requestNotificationsPermission();

    final iosPlugin = _localNotifications.resolvePlatformSpecificImplementation<
        IOSFlutterLocalNotificationsPlugin>();
    await iosPlugin?.requestPermissions(
      alert: true,
      badge: true,
      sound: true,
    );

    final macOsPlugin =
        _localNotifications.resolvePlatformSpecificImplementation<
            MacOSFlutterLocalNotificationsPlugin>();
    await macOsPlugin?.requestPermissions(
      alert: true,
      badge: true,
      sound: true,
    );
  }

  Future<PushRegistration?> _buildRegistration(String pushToken) async {
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
      final androidInfo = await deviceInfoPlugin.androidInfo;
      deviceId = androidInfo.id;
    }

    return PushRegistration(
      platform: platform,
      deviceId: deviceId,
      pushToken: pushToken,
      appVersion: packageInfo.version,
      locale: locale,
      timezone: timezone,
    );
  }

  Future<void> _registerToken(
    AuthSession session,
    PushRegistration registration,
  ) async {
    final authService = _authService;
    if (authService == null) {
      return;
    }
    await authService.registerDevice(
      accessToken: session.accessToken,
      platform: registration.platform,
      deviceId: registration.deviceId,
      pushToken: registration.pushToken,
      appVersion: registration.appVersion,
      locale: registration.locale,
      timezone: registration.timezone,
    );
  }

  Future<void> _showForegroundNotification(RemoteMessage message) async {
    if (!_localNotificationsReady) {
      return;
    }

    final title =
        message.notification?.title ?? buildFallbackTitle(message.data);
    final body = message.notification?.body ?? buildFallbackBody(message.data);
    if (title.isEmpty && body.isEmpty) {
      return;
    }

    await _localNotifications.show(
      message.messageId.hashCode ^ title.hashCode ^ body.hashCode,
      title,
      body,
      _notificationDetails(),
      payload: jsonEncode(message.data),
    );
  }

  static String buildFallbackTitle(Map<String, dynamic> data) {
    final type = (data['type'] ?? '').toString();
    if (type == 'message') {
      return 'Yeni mesaj';
    }
    if (type == 'appointment') {
      return 'Randevu güncellendi';
    }
    if (type == 'request') {
      return 'Talep güncellendi';
    }
    return 'UstaBul';
  }

  static String buildFallbackBody(Map<String, dynamic> data) {
    final requestCode = (data['request_code'] ?? '').toString();
    final status = (data['status'] ?? '').toString();
    if (requestCode.isNotEmpty && status.isNotEmpty) {
      return 'Talep $requestCode: $status';
    }
    if (requestCode.isNotEmpty) {
      return 'Talep $requestCode için yeni bildirim var.';
    }
    return 'Yeni bir bildiriminiz var.';
  }
}
