class AuthSession {
  const AuthSession({
    required this.accessToken,
    required this.refreshToken,
    required this.role,
    required this.user,
  });

  final String accessToken;
  final String refreshToken;
  final String role;
  final Map<String, dynamic> user;

  bool get isProvider => role == 'provider';

  AuthSession copyWith({
    String? accessToken,
    String? refreshToken,
    String? role,
    Map<String, dynamic>? user,
  }) {
    return AuthSession(
      accessToken: accessToken ?? this.accessToken,
      refreshToken: refreshToken ?? this.refreshToken,
      role: role ?? this.role,
      user: user ?? this.user,
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'access_token': accessToken,
      'refresh_token': refreshToken,
      'role': role,
      'user': user,
    };
  }

  factory AuthSession.fromJson(Map<String, dynamic> data) {
    final userData = data['user'];
    return AuthSession(
      accessToken: (data['access_token'] ?? data['access'] ?? '').toString(),
      refreshToken: (data['refresh_token'] ?? data['refresh'] ?? '').toString(),
      role: (data['role'] ?? (userData is Map ? userData['role'] : '') ?? '').toString(),
      user: userData is Map<String, dynamic> ? userData : <String, dynamic>{},
    );
  }
}
