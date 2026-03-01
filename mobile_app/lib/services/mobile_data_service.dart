import 'api_client.dart';

class MobileDataService {
  const MobileDataService(this._apiClient);

  final ApiClient _apiClient;

  Future<Map<String, dynamic>> fetchCustomerRequests({
    required String accessToken,
    int limit = 30,
    int offset = 0,
  }) async {
    final response = await _apiClient.get(
      '/mobile/api/v1/customer/requests/',
      accessToken: accessToken,
      queryParameters: {
        'limit': limit,
        'offset': offset,
      },
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Talep listesi yaniti gecersiz.');
    }
    return response;
  }

  Future<Map<String, dynamic>> fetchProviderDashboard({
    required String accessToken,
    int threadLimit = 20,
  }) async {
    final response = await _apiClient.get(
      '/mobile/api/v1/provider/dashboard/',
      accessToken: accessToken,
      queryParameters: {'thread_limit': threadLimit},
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Usta panel yaniti gecersiz.');
    }
    return response;
  }

  Future<Map<String, dynamic>> fetchRequestMessages({
    required String accessToken,
    required int requestId,
    int afterId = 0,
  }) async {
    final response = await _apiClient.get(
      '/mobile/api/v1/requests/$requestId/messages/',
      accessToken: accessToken,
      queryParameters: {'after_id': afterId},
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Mesaj yaniti gecersiz.');
    }
    return response;
  }

  Future<Map<String, dynamic>> sendRequestMessage({
    required String accessToken,
    required int requestId,
    required String body,
  }) async {
    final response = await _apiClient.post(
      '/mobile/api/v1/requests/$requestId/messages/',
      accessToken: accessToken,
      data: {'body': body},
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Mesaj gonderme yaniti gecersiz.');
    }
    return response;
  }
}
