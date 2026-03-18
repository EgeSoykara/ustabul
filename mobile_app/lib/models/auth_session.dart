class AuthSession {
  const AuthSession({
    required this.accessToken,
    required this.refreshToken,
    required this.role,
    required this.user,
    required this.snapshot,
  });

  final String accessToken;
  final String refreshToken;
  final String role;
  final Map<String, dynamic> user;
  final Map<String, dynamic> snapshot;

  bool get isProvider => role == 'provider';

  AuthSession copyWith({
    String? accessToken,
    String? refreshToken,
    String? role,
    Map<String, dynamic>? user,
    Map<String, dynamic>? snapshot,
  }) {
    return AuthSession(
      accessToken: accessToken ?? this.accessToken,
      refreshToken: refreshToken ?? this.refreshToken,
      role: role ?? this.role,
      user: user ?? this.user,
      snapshot: snapshot ?? this.snapshot,
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'access_token': accessToken,
      'refresh_token': refreshToken,
      'role': role,
      'user': user,
      'snapshot': snapshot,
    };
  }

  factory AuthSession.fromJson(Map<String, dynamic> data) {
    final userData = data['user'];
    final snapshotData = data['snapshot'];
    return AuthSession(
      accessToken: (data['access_token'] ?? data['access'] ?? '').toString(),
      refreshToken: (data['refresh_token'] ?? data['refresh'] ?? '').toString(),
      role: (data['role'] ?? (userData is Map ? userData['role'] : '') ?? '')
          .toString(),
      user: userData is Map<String, dynamic> ? userData : <String, dynamic>{},
      snapshot: snapshotData is Map<String, dynamic>
          ? snapshotData
          : <String, dynamic>{},
    );
  }
}
