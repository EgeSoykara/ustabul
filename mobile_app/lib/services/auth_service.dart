import '../models/auth_session.dart';
import 'api_client.dart';

class AuthService {
  const AuthService(this._apiClient);

  final ApiClient _apiClient;

  Future<AuthSession> login({
    required String username,
    required String password,
  }) async {
    final response = await _apiClient.post(
      '/mobile/api/v1/auth/login/',
      data: {
        'username': username,
        'password': password,
      },
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Giriş yanıtı geçersiz.');
    }
    final userData = response['user'];
    if (userData is! Map<String, dynamic>) {
      throw const ApiException('Kullanıcı bilgisi alınamadı.');
    }
    return AuthSession.fromJson({
      'access_token': response['access'],
      'refresh_token': response['refresh'],
      'role': userData['role'],
      'user': userData,
      'snapshot': response['snapshot'] is Map<String, dynamic>
          ? response['snapshot'] as Map<String, dynamic>
          : <String, dynamic>{},
    });
  }

  Future<String> refreshAccessToken(String refreshToken) async {
    final response = await _apiClient.post(
      '/mobile/api/v1/auth/refresh/',
      data: {'refresh': refreshToken},
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Token yenileme yanıtı geçersiz.');
    }
    final access = (response['access'] ?? '').toString();
    if (access.isEmpty) {
      throw const ApiException('Yeni erişim anahtarı alınamadı.');
    }
    return access;
  }

  Future<Map<String, dynamic>> fetchMe(String accessToken) async {
    final response = await _apiClient.get(
      '/mobile/api/v1/me/',
      accessToken: accessToken,
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Profil yanıtı geçersiz.');
    }
    return response;
  }

  Future<void> registerDevice({
    required String accessToken,
    required String platform,
    required String deviceId,
    required String pushToken,
    required String appVersion,
    required String locale,
    required String timezone,
  }) async {
    await _apiClient.post(
      '/mobile/api/v1/devices/register/',
      accessToken: accessToken,
      data: {
        'platform': platform,
        'device_id': deviceId,
        'push_token': pushToken,
        'app_version': appVersion,
        'locale': locale,
        'timezone': timezone,
      },
    );
  }
}
