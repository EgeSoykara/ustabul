import 'package:dio/dio.dart';

class ApiException implements Exception {
  const ApiException(this.message, {this.statusCode});

  final String message;
  final int? statusCode;

  @override
  String toString() => message;
}

class ApiClient {
  ApiClient({required String baseUrl})
      : _dio = Dio(
          BaseOptions(
            baseUrl: baseUrl,
            connectTimeout: const Duration(seconds: 15),
            receiveTimeout: const Duration(seconds: 20),
            sendTimeout: const Duration(seconds: 20),
            headers: const {
              'Accept': 'application/json',
            },
          ),
        );

  final Dio _dio;

  Future<dynamic> get(
    String path, {
    String? accessToken,
    Map<String, dynamic>? queryParameters,
  }) async {
    try {
      final response = await _dio.get<dynamic>(
        path,
        queryParameters: queryParameters,
        options: Options(headers: _buildHeaders(accessToken)),
      );
      return response.data;
    } on DioException catch (error) {
      throw _toApiException(error);
    }
  }

  Future<dynamic> post(
    String path, {
    String? accessToken,
    dynamic data,
  }) async {
    try {
      final response = await _dio.post<dynamic>(
        path,
        data: data,
        options: Options(headers: _buildHeaders(accessToken)),
      );
      return response.data;
    } on DioException catch (error) {
      throw _toApiException(error);
    }
  }

  Future<dynamic> put(
    String path, {
    String? accessToken,
    dynamic data,
  }) async {
    try {
      final response = await _dio.put<dynamic>(
        path,
        data: data,
        options: Options(headers: _buildHeaders(accessToken)),
      );
      return response.data;
    } on DioException catch (error) {
      throw _toApiException(error);
    }
  }

  Map<String, String> _buildHeaders(String? accessToken) {
    final headers = <String, String>{'Content-Type': 'application/json'};
    if (accessToken != null && accessToken.isNotEmpty) {
      headers['Authorization'] = 'Bearer $accessToken';
    }
    return headers;
  }

  ApiException _toApiException(DioException error) {
    final statusCode = error.response?.statusCode;
    final raw = error.response?.data;
    if (raw is Map<String, dynamic>) {
      final fieldErrors = raw['errors'];
      if (fieldErrors is Map) {
        final messages = <String>[];
        for (final value in fieldErrors.values) {
          if (value is List) {
            for (final item in value) {
              final text = item.toString().trim();
              if (text.isNotEmpty) {
                messages.add(text);
              }
            }
          } else {
            final text = value.toString().trim();
            if (text.isNotEmpty) {
              messages.add(text);
            }
          }
        }
        if (messages.isNotEmpty) {
          return ApiException(messages.join('\n'), statusCode: statusCode);
        }
      }
      final detail = (raw['message'] ?? raw['detail'] ?? '').toString();
      if (detail.isNotEmpty) {
        return ApiException(detail, statusCode: statusCode);
      }
    }
    return ApiException(
      error.message ?? 'Sunucu hatası oluştu.',
      statusCode: statusCode,
    );
  }
}
