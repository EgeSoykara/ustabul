import 'api_client.dart';

class MobileDataService {
  const MobileDataService(this._apiClient);

  final ApiClient _apiClient;

  Future<Map<String, dynamic>> fetchMarketplaceBootstrap({
    String? accessToken,
    int? preferredProviderId,
  }) async {
    final response = await _apiClient.get(
      '/mobile/api/v1/marketplace/bootstrap/',
      accessToken: accessToken,
      queryParameters: preferredProviderId == null
          ? null
          : {'preferred_provider_id': preferredProviderId},
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Pazar yeri verisi okunamadı.');
    }
    return response;
  }

  Future<Map<String, dynamic>> fetchProviders({
    String? accessToken,
    String? query,
    int? serviceTypeId,
    String? city,
    String? district,
    String sortBy = 'relevance',
    double? minRating,
    int? minReviews,
    int limit = 20,
    int offset = 0,
  }) async {
    final queryParameters = <String, dynamic>{
      'limit': limit,
      'offset': offset,
      'sort_by': sortBy,
    };
    if ((query ?? '').trim().isNotEmpty) {
      queryParameters['query'] = query!.trim();
    }
    if (serviceTypeId != null && serviceTypeId > 0) {
      queryParameters['service_type'] = serviceTypeId;
    }
    if ((city ?? '').trim().isNotEmpty) {
      queryParameters['city'] = city!.trim();
    }
    if ((district ?? '').trim().isNotEmpty) {
      queryParameters['district'] = district!.trim();
    }
    if (minRating != null) {
      queryParameters['min_rating'] = minRating.toStringAsFixed(1);
    }
    if (minReviews != null) {
      queryParameters['min_reviews'] = minReviews;
    }

    final response = await _apiClient.get(
      '/mobile/api/v1/marketplace/providers/',
      accessToken: accessToken,
      queryParameters: queryParameters,
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Usta listesi yanıtı geçersiz.');
    }
    return response;
  }

  Future<Map<String, dynamic>> fetchProviderDetail({
    String? accessToken,
    required int providerId,
  }) async {
    final response = await _apiClient.get(
      '/mobile/api/v1/marketplace/providers/$providerId/',
      accessToken: accessToken,
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Usta detayı okunamadı.');
    }
    return response;
  }

  Future<Map<String, dynamic>> createRequest({
    required String accessToken,
    required String customerName,
    required String customerPhone,
    required int serviceTypeId,
    required String city,
    required String district,
    required String details,
    int? preferredProviderId,
  }) async {
    final payload = <String, dynamic>{
      'customer_name': customerName,
      'customer_phone': customerPhone,
      'service_type': serviceTypeId,
      'city': city,
      'district': district,
      'details': details,
    };
    if (preferredProviderId != null && preferredProviderId > 0) {
      payload['preferred_provider_id'] = preferredProviderId;
    }

    final response = await _apiClient.post(
      '/mobile/api/v1/customer/requests/create/',
      accessToken: accessToken,
      data: payload,
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Talep oluşturma yanıtı geçersiz.');
    }
    return response;
  }

  Future<Map<String, dynamic>> fetchCustomerRequests({
    required String accessToken,
    int limit = 30,
    int offset = 0,
    String? scope,
  }) async {
    final queryParameters = <String, dynamic>{
      'limit': limit,
      'offset': offset,
    };
    if ((scope ?? '').trim().isNotEmpty) {
      queryParameters['scope'] = scope!.trim();
    }
    final response = await _apiClient.get(
      '/mobile/api/v1/customer/requests/',
      accessToken: accessToken,
      queryParameters: queryParameters,
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Talep listesi yanıtı geçersiz.');
    }
    return response;
  }

  Future<Map<String, dynamic>> fetchCustomerRequestsSummary({
    required String accessToken,
    String? scope,
  }) async {
    final queryParameters = <String, dynamic>{
      'summary_only': '1',
    };
    if ((scope ?? '').trim().isNotEmpty) {
      queryParameters['scope'] = scope!.trim();
    }
    final response = await _apiClient.get(
      '/mobile/api/v1/customer/requests/',
      accessToken: accessToken,
      queryParameters: queryParameters,
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Talep özeti yanıtı geçersiz.');
    }
    return response;
  }

  Future<Map<String, dynamic>> fetchRequestDetail({
    required String accessToken,
    required int requestId,
  }) async {
    final response = await _apiClient.get(
      '/mobile/api/v1/requests/$requestId/detail/',
      accessToken: accessToken,
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Talep detayı okunamadı.');
    }
    return response;
  }

  Future<Map<String, dynamic>> fetchRequestDetailSummary({
    required String accessToken,
    required int requestId,
  }) async {
    final response = await _apiClient.get(
      '/mobile/api/v1/requests/$requestId/detail/',
      accessToken: accessToken,
      queryParameters: const {'summary_only': '1'},
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Talep detay özeti okunamadı.');
    }
    return response;
  }

  Future<Map<String, dynamic>> cancelRequest({
    required String accessToken,
    required int requestId,
  }) async {
    final response = await _apiClient.post(
      '/mobile/api/v1/customer/requests/$requestId/cancel/',
      accessToken: accessToken,
      data: const <String, dynamic>{},
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Talep iptal edilemedi.');
    }
    return response;
  }

  Future<Map<String, dynamic>> completeRequest({
    required String accessToken,
    required int requestId,
  }) async {
    final response = await _apiClient.post(
      '/mobile/api/v1/customer/requests/$requestId/complete/',
      accessToken: accessToken,
      data: const <String, dynamic>{},
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Talep tamamlanamadı.');
    }
    return response;
  }

  Future<Map<String, dynamic>> submitRequestRating({
    required String accessToken,
    required int requestId,
    required int score,
    String comment = '',
  }) async {
    final response = await _apiClient.post(
      '/mobile/api/v1/customer/requests/$requestId/rating/',
      accessToken: accessToken,
      data: {
        'score': score,
        'comment': comment,
      },
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Puan kaydedilemedi.');
    }
    return response;
  }

  Future<Map<String, dynamic>> selectOffer({
    required String accessToken,
    required int requestId,
    required int offerId,
  }) async {
    final response = await _apiClient.post(
      '/mobile/api/v1/customer/requests/$requestId/offers/$offerId/select/',
      accessToken: accessToken,
      data: const <String, dynamic>{},
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Usta seçimi tamamlanamadı.');
    }
    return response;
  }

  Future<Map<String, dynamic>> createAppointment({
    required String accessToken,
    required int requestId,
    required String scheduledFor,
    String customerNote = '',
  }) async {
    final response = await _apiClient.post(
      '/mobile/api/v1/customer/requests/$requestId/appointments/',
      accessToken: accessToken,
      data: {
        'scheduled_for': scheduledFor,
        'customer_note': customerNote,
      },
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Randevu oluşturulamadı.');
    }
    return response;
  }

  Future<Map<String, dynamic>> cancelAppointment({
    required String accessToken,
    required int requestId,
  }) async {
    final response = await _apiClient.post(
      '/mobile/api/v1/customer/requests/$requestId/appointments/cancel/',
      accessToken: accessToken,
      data: const <String, dynamic>{},
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Randevu iptal edilemedi.');
    }
    return response;
  }

  Future<Map<String, dynamic>> fetchProviderDashboard({
    required String accessToken,
    int threadLimit = 100,
  }) async {
    final response = await _apiClient.get(
      '/mobile/api/v1/provider/dashboard/',
      accessToken: accessToken,
      queryParameters: {'thread_limit': threadLimit},
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Usta paneli yanıtı geçersiz.');
    }
    return response;
  }

  Future<Map<String, dynamic>> fetchProviderDashboardSummary({
    required String accessToken,
  }) async {
    final response = await _apiClient.get(
      '/mobile/api/v1/provider/dashboard/',
      accessToken: accessToken,
      queryParameters: const {'summary_only': '1'},
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Usta paneli özeti okunamadı.');
    }
    return response;
  }

  Future<Map<String, dynamic>> acceptProviderOffer({
    required String accessToken,
    required int offerId,
    String quoteNote = '',
  }) async {
    final response = await _apiClient.post(
      '/mobile/api/v1/provider/offers/$offerId/accept/',
      accessToken: accessToken,
      data: {'quote_note': quoteNote},
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Teklif kabul edilemedi.');
    }
    return response;
  }

  Future<Map<String, dynamic>> rejectProviderOffer({
    required String accessToken,
    required int offerId,
  }) async {
    final response = await _apiClient.post(
      '/mobile/api/v1/provider/offers/$offerId/reject/',
      accessToken: accessToken,
      data: const <String, dynamic>{},
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Teklif reddedilemedi.');
    }
    return response;
  }

  Future<Map<String, dynamic>> withdrawProviderOffer({
    required String accessToken,
    required int offerId,
  }) async {
    final response = await _apiClient.post(
      '/mobile/api/v1/provider/offers/$offerId/withdraw/',
      accessToken: accessToken,
      data: const <String, dynamic>{},
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Teklif geri çekilemedi.');
    }
    return response;
  }

  Future<Map<String, dynamic>> confirmProviderAppointment({
    required String accessToken,
    required int appointmentId,
    String providerNote = '',
  }) async {
    final response = await _apiClient.post(
      '/mobile/api/v1/provider/appointments/$appointmentId/confirm/',
      accessToken: accessToken,
      data: {'provider_note': providerNote},
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Randevu onaylanamadı.');
    }
    return response;
  }

  Future<Map<String, dynamic>> rejectProviderAppointment({
    required String accessToken,
    required int appointmentId,
    String providerNote = '',
  }) async {
    final response = await _apiClient.post(
      '/mobile/api/v1/provider/appointments/$appointmentId/reject/',
      accessToken: accessToken,
      data: {'provider_note': providerNote},
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Randevu reddedilemedi.');
    }
    return response;
  }

  Future<Map<String, dynamic>> completeProviderAppointment({
    required String accessToken,
    required int appointmentId,
  }) async {
    final response = await _apiClient.post(
      '/mobile/api/v1/provider/appointments/$appointmentId/complete/',
      accessToken: accessToken,
      data: const <String, dynamic>{},
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('İş tamamlanamadı.');
    }
    return response;
  }

  Future<Map<String, dynamic>> releaseProviderRequest({
    required String accessToken,
    required int requestId,
  }) async {
    final response = await _apiClient.post(
      '/mobile/api/v1/provider/requests/$requestId/release/',
      accessToken: accessToken,
      data: const <String, dynamic>{},
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Eşleşme sonlandırılamadı.');
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
      throw const ApiException('Mesaj yanıtı geçersiz.');
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
      throw const ApiException('Mesaj gönderme yanıtı geçersiz.');
    }
    return response;
  }

  Future<Map<String, dynamic>> fetchNotifications({
    required String accessToken,
    String category = 'all',
    int limit = 30,
  }) async {
    final response = await _apiClient.get(
      '/mobile/api/v1/notifications/',
      accessToken: accessToken,
      queryParameters: {
        'category': category,
        'limit': limit,
      },
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Bildirim yanıtı geçersiz.');
    }
    return response;
  }

  Future<Map<String, dynamic>> fetchNotificationsSummary({
    required String accessToken,
    String category = 'all',
  }) async {
    final response = await _apiClient.get(
      '/mobile/api/v1/notifications/',
      accessToken: accessToken,
      queryParameters: {
        'category': category,
        'summary_only': '1',
      },
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Bildirim özeti okunamadı.');
    }
    return response;
  }

  Future<Map<String, dynamic>> markNotificationRead({
    required String accessToken,
    required String entryId,
  }) async {
    final response = await _apiClient.post(
      '/mobile/api/v1/notifications/$entryId/read/',
      accessToken: accessToken,
      data: const <String, dynamic>{},
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Bildirim güncelleme yanıtı geçersiz.');
    }
    return response;
  }

  Future<Map<String, dynamic>> markAllNotificationsRead({
    required String accessToken,
  }) async {
    final response = await _apiClient.post(
      '/mobile/api/v1/notifications/read-all/',
      accessToken: accessToken,
      data: const <String, dynamic>{},
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Bildirim güncelleme yanıtı geçersiz.');
    }
    return response;
  }

  Future<Map<String, dynamic>> fetchNotificationPreferences({
    required String accessToken,
  }) async {
    final response = await _apiClient.get(
      '/mobile/api/v1/notification-preferences/',
      accessToken: accessToken,
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Bildirim tercihleri okunamadı.');
    }
    return response;
  }

  Future<Map<String, dynamic>> updateNotificationPreferences({
    required String accessToken,
    required bool allowMessageNotifications,
    required bool allowRequestNotifications,
    required bool allowAppointmentNotifications,
  }) async {
    final response = await _apiClient.put(
      '/mobile/api/v1/notification-preferences/',
      accessToken: accessToken,
      data: {
        'allow_message_notifications': allowMessageNotifications,
        'allow_request_notifications': allowRequestNotifications,
        'allow_appointment_notifications': allowAppointmentNotifications,
      },
    );
    if (response is! Map<String, dynamic>) {
      throw const ApiException('Bildirim tercihleri güncellenemedi.');
    }
    return response;
  }
}
