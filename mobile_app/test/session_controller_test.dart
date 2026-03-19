import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:ustabul_mobile/models/auth_session.dart';
import 'package:ustabul_mobile/services/api_client.dart';
import 'package:ustabul_mobile/services/auth_service.dart';
import 'package:ustabul_mobile/services/auth_storage.dart';
import 'package:ustabul_mobile/services/push_service.dart';
import 'package:ustabul_mobile/services/web_auth_service.dart';
import 'package:ustabul_mobile/state/session_controller.dart';
import 'package:webview_flutter_platform_interface/webview_flutter_platform_interface.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  WebViewPlatform.instance = _FakeWebViewPlatform();

  group('SessionController.ensureAccessToken', () {
    test('reuses current token when expiry is far away', () async {
      final apiClient = _FakeApiClient();
      final storage = _FakeAuthStorage(
        session: _buildSession(
          accessToken: _buildJwt(DateTime.now().add(const Duration(hours: 1))),
        ),
      );
      final controller = SessionController(
        authService: AuthService(apiClient),
        authStorage: storage,
        pushService: _FakePushService(),
        webAuthService: _FakeWebAuthService(),
      );

      await controller.initialize();
      final token = await controller.ensureAccessToken();

      expect(token, storage.savedSession!.accessToken);
      expect(apiClient.meCalls, 1);
      expect(apiClient.refreshCalls, 0);
    });

    test('refreshes token when expiry is near', () async {
      final refreshedToken =
          _buildJwt(DateTime.now().add(const Duration(hours: 2)));
      final apiClient = _FakeApiClient(refreshedToken: refreshedToken);
      final storage = _FakeAuthStorage(
        session: _buildSession(
          accessToken:
              _buildJwt(DateTime.now().add(const Duration(seconds: 30))),
        ),
      );
      final controller = SessionController(
        authService: AuthService(apiClient),
        authStorage: storage,
        pushService: _FakePushService(),
        webAuthService: _FakeWebAuthService(),
      );

      await controller.initialize();
      final token = await controller.ensureAccessToken();

      expect(token, refreshedToken);
      expect(apiClient.refreshCalls, 1);
      expect(storage.savedSession!.accessToken, refreshedToken);
      expect(storage.savedSession!.accessTokenExpiresAt, isNotNull);
    });
  });
}

AuthSession _buildSession({required String accessToken}) {
  return AuthSession.fromJson({
    'access_token': accessToken,
    'refresh_token': 'refresh-token',
    'role': 'customer',
    'user': const {'role': 'customer', 'username': 'tester'},
    'snapshot': const {},
  });
}

String _buildJwt(DateTime expiresAt) {
  final header = base64Url.encode(utf8.encode('{"alg":"none","typ":"JWT"}'));
  final payload = base64Url.encode(
    utf8.encode(
      jsonEncode({
        'exp': expiresAt.toUtc().millisecondsSinceEpoch ~/ 1000,
      }),
    ),
  );
  return '$header.$payload.signature';
}

class _FakeApiClient extends ApiClient {
  _FakeApiClient({this.refreshedToken = ''})
      : super(baseUrl: 'https://example.com');

  int meCalls = 0;
  int refreshCalls = 0;
  final String refreshedToken;

  @override
  Future<dynamic> get(
    String path, {
    String? accessToken,
    Map<String, dynamic>? queryParameters,
  }) async {
    if (path == '/mobile/api/v1/me/') {
      meCalls += 1;
      return {
        'user': {
          'role': 'customer',
          'username': 'tester',
        },
        'snapshot': const {},
      };
    }
    throw ApiException('unexpected get: $path');
  }

  @override
  Future<dynamic> post(
    String path, {
    String? accessToken,
    dynamic data,
  }) async {
    if (path == '/mobile/api/v1/auth/refresh/') {
      refreshCalls += 1;
      return {
        'access': refreshedToken,
      };
    }
    throw ApiException('unexpected post: $path');
  }
}

class _FakeAuthStorage extends AuthStorage {
  _FakeAuthStorage({this.session});

  AuthSession? session;
  AuthSession? savedSession;
  bool cleared = false;

  @override
  Future<void> saveSession(AuthSession session) async {
    savedSession = session;
    this.session = session;
  }

  @override
  Future<AuthSession?> loadSession() async => session;

  @override
  Future<void> clear() async {
    cleared = true;
    session = null;
    savedSession = null;
  }
}

class _FakePushService extends PushService {
  _FakePushService() : super();

  int initializeCalls = 0;
  bool disposed = false;

  @override
  Future<void> initializeAndRegister(AuthSession session) async {
    initializeCalls += 1;
  }

  @override
  Future<void> dispose() async {
    disposed = true;
  }
}

class _FakeWebAuthService extends WebAuthService {
  _FakeWebAuthService() : super(siteUrl: 'https://example.com');

  @override
  Future<void> restoreSession() async {}

  @override
  Future<bool> ensureSessionAvailable() async => true;

  @override
  Future<void> clear() async {}

  @override
  Future<void> login({
    required String username,
    required String password,
    required bool isProvider,
  }) async {}
}

class _FakeWebViewPlatform extends WebViewPlatform {
  @override
  PlatformWebViewCookieManager createPlatformCookieManager(
    PlatformWebViewCookieManagerCreationParams params,
  ) {
    return _FakePlatformWebViewCookieManager(params);
  }
}

class _FakePlatformWebViewCookieManager extends PlatformWebViewCookieManager {
  _FakePlatformWebViewCookieManager(super.params) : super.implementation();

  @override
  Future<bool> clearCookies() async => true;

  @override
  Future<void> setCookie(WebViewCookie cookie) async {}
}
