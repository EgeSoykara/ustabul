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
      throw const ApiException('Giris yaniti gecersiz.');
    }
    final userData = response['user'];
    if (userData is! Map<String, dynamic>) {
      throw const ApiException('Kullanici bilgisi alinamadi.');
    }
    return AuthSession(
      accessToken: (response['access'] ?? '').toString(),
      refreshToken: (response['refresh'] ?? '').toString(),
      role: (userData['role'] ?? '').toString(),
      user: userData,
    );
  }

  Future<String> refreshAccessToken(String refreshToken) async {
    final response = await _apiClient.post(
      '/mobile/api/v1/auth/refresh/',
      data: {'refresh': refreshToken},
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Token yenileme yaniti gecersiz.');
    }
    final access = (response['access'] ?? '').toString();
    if (access.isEmpty) {
      throw const ApiException('Yeni access token alinamadi.');
    }
    return access;
  }

  Future<Map<String, dynamic>> fetchMe(String accessToken) async {
    final response = await _apiClient.get(
      '/mobile/api/v1/me/',
      accessToken: accessToken,
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Profil yaniti gecersiz.');
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
