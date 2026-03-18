class WebSession {
  const WebSession({
    required this.sessionId,
    required this.csrfToken,
    required this.isProvider,
  });

  final String sessionId;
  final String csrfToken;
  final bool isProvider;

  Map<String, dynamic> toJson() {
    return {
      'session_id': sessionId,
      'csrf_token': csrfToken,
      'is_provider': isProvider,
    };
  }

  factory WebSession.fromJson(Map<String, dynamic> data) {
    return WebSession(
      sessionId: (data['session_id'] ?? '').toString(),
      csrfToken: (data['csrf_token'] ?? '').toString(),
      isProvider: data['is_provider'] == true,
    );
  }
}
