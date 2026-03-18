import 'package:dio/dio.dart';
import 'package:webview_flutter/webview_flutter.dart';

import '../models/web_session.dart';
import 'api_client.dart';
import 'web_session_storage.dart';

class WebAuthService {
  WebAuthService({
    required String siteUrl,
    WebSessionStorage? storage,
    WebViewCookieManager? cookieManager,
  })  : _siteUri = Uri.parse(siteUrl),
        _storage = storage ?? WebSessionStorage(),
        _cookieManager = cookieManager ?? WebViewCookieManager(),
        _dio = Dio(
          BaseOptions(
            baseUrl: siteUrl,
            connectTimeout: const Duration(seconds: 15),
            receiveTimeout: const Duration(seconds: 20),
            sendTimeout: const Duration(seconds: 20),
            responseType: ResponseType.plain,
            validateStatus: (status) => status != null && status < 500,
          ),
        );

  final Uri _siteUri;
  final WebSessionStorage _storage;
  final WebViewCookieManager _cookieManager;
  final Dio _dio;

  Future<void> restoreSession() async {
    final session = await _storage.loadSession();
    if (session == null) {
      return;
    }
    await _applySession(session);
  }

  Future<bool> ensureSessionAvailable() async {
    final session = await _storage.loadSession();
    if (session == null) {
      return false;
    }
    await _applySession(session);
    return true;
  }

  Future<void> login({
    required String username,
    required String password,
    required bool isProvider,
  }) async {
    final loginPath = isProvider ? '/usta/giris/' : '/musteri/giris/';
    final loginPageResponse = await _dio.get<String>(loginPath);
    final loginPageBody = loginPageResponse.data ?? '';
    final csrfToken = _extractCsrfToken(loginPageBody);
    final csrfCookie =
        _extractCookieValue(loginPageResponse.headers, 'csrftoken') ??
            csrfToken;

    if (csrfToken.isEmpty || csrfCookie.isEmpty) {
      throw const ApiException('Site oturumu başlatılamadı.');
    }

    final encodedBody = _encodeFormBody({
      'username': username,
      'password': password,
      'csrfmiddlewaretoken': csrfToken,
    });

    final loginResponse = await _dio.post<String>(
      loginPath,
      data: encodedBody,
      options: Options(
        contentType: Headers.formUrlEncodedContentType,
        headers: {
          'Cookie': 'csrftoken=$csrfCookie',
          'Referer': _siteUri.resolve(loginPath).toString(),
          'X-CSRFToken': csrfCookie,
        },
        followRedirects: false,
      ),
    );

    final sessionId = _extractCookieValue(loginResponse.headers, 'sessionid');
    final nextCsrfToken =
        _extractCookieValue(loginResponse.headers, 'csrftoken') ?? csrfCookie;

    if (sessionId == null || sessionId.isEmpty) {
      throw const ApiException('Site oturumu açılamadı.');
    }

    final session = WebSession(
      sessionId: sessionId,
      csrfToken: nextCsrfToken,
      isProvider: isProvider,
    );
    await _applySession(session);
    await _storage.saveSession(session);
  }

  Future<void> clear() async {
    await _storage.clear();
    await _cookieManager.clearCookies();
  }

  Future<void> _applySession(WebSession session) async {
    await _cookieManager.setCookie(
      WebViewCookie(
        name: 'sessionid',
        value: session.sessionId,
        domain: _siteUri.host,
        path: '/',
      ),
    );
    await _cookieManager.setCookie(
      WebViewCookie(
        name: 'csrftoken',
        value: session.csrfToken,
        domain: _siteUri.host,
        path: '/',
      ),
    );
  }

  String _extractCsrfToken(String body) {
    final match = RegExp(
      "name=[\"']csrfmiddlewaretoken[\"']\\s+value=[\"']([^\"']+)[\"']",
    ).firstMatch(body);
    return match?.group(1)?.trim() ?? '';
  }

  String? _extractCookieValue(Headers headers, String name) {
    final rawCookies = headers.map['set-cookie'] ?? const <String>[];
    final prefix = '$name=';
    for (final cookie in rawCookies) {
      final segments = cookie.split(';');
      for (final segment in segments) {
        final trimmed = segment.trim();
        if (trimmed.startsWith(prefix)) {
          return trimmed.substring(prefix.length);
        }
      }
    }
    return null;
  }

  String _encodeFormBody(Map<String, String> fields) {
    return fields.entries
        .map(
          (entry) =>
              '${Uri.encodeQueryComponent(entry.key)}=${Uri.encodeQueryComponent(entry.value)}',
        )
        .join('&');
  }
}
