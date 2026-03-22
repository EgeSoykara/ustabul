import 'dart:convert';

class AuthSession {
  const AuthSession({
    required this.accessToken,
    required this.refreshToken,
    required this.role,
    required this.user,
    required this.snapshot,
    required this.realtimeEnabled,
    required this.accessTokenExpiresAt,
  });

  final String accessToken;
  final String refreshToken;
  final String role;
  final Map<String, dynamic> user;
  final Map<String, dynamic> snapshot;
  final bool realtimeEnabled;
  final DateTime? accessTokenExpiresAt;

  bool get isProvider => role == 'provider';

  bool shouldRefreshAccessToken({
    Duration leeway = const Duration(minutes: 2),
  }) {
    final expiry = accessTokenExpiresAt;
    if (expiry == null) {
      return false;
    }
    return DateTime.now().isAfter(expiry.subtract(leeway));
  }

  AuthSession copyWith({
    String? accessToken,
    String? refreshToken,
    String? role,
    Map<String, dynamic>? user,
    Map<String, dynamic>? snapshot,
    bool? realtimeEnabled,
    DateTime? accessTokenExpiresAt,
  }) {
    return AuthSession(
      accessToken: accessToken ?? this.accessToken,
      refreshToken: refreshToken ?? this.refreshToken,
      role: role ?? this.role,
      user: user ?? this.user,
      snapshot: snapshot ?? this.snapshot,
      realtimeEnabled: realtimeEnabled ?? this.realtimeEnabled,
      accessTokenExpiresAt: accessTokenExpiresAt ?? this.accessTokenExpiresAt,
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'access_token': accessToken,
      'refresh_token': refreshToken,
      'role': role,
      'user': user,
      'snapshot': snapshot,
      'realtime_enabled': realtimeEnabled,
      'access_token_expires_at': accessTokenExpiresAt?.toIso8601String(),
    };
  }

  factory AuthSession.fromJson(Map<String, dynamic> data) {
    final userData = data['user'];
    final snapshotData = data['snapshot'];
    final accessToken =
        (data['access_token'] ?? data['access'] ?? '').toString();
    final rawExpiry = (data['access_token_expires_at'] ?? '').toString();
    return AuthSession(
      accessToken: accessToken,
      refreshToken: (data['refresh_token'] ?? data['refresh'] ?? '').toString(),
      role: (data['role'] ?? (userData is Map ? userData['role'] : '') ?? '')
          .toString(),
      user: userData is Map<String, dynamic> ? userData : <String, dynamic>{},
      snapshot: snapshotData is Map<String, dynamic>
          ? snapshotData
          : <String, dynamic>{},
      realtimeEnabled: data['realtime_enabled'] == true,
      accessTokenExpiresAt: rawExpiry.isNotEmpty
          ? DateTime.tryParse(rawExpiry)?.toLocal()
          : _extractJwtExpiry(accessToken),
    );
  }

  static DateTime? _extractJwtExpiry(String token) {
    final segments = token.split('.');
    if (segments.length < 2) {
      return null;
    }
    final normalized = base64Url.normalize(segments[1]);
    try {
      final decoded = utf8.decode(base64Url.decode(normalized));
      final payload = jsonDecode(decoded);
      if (payload is! Map<String, dynamic>) {
        return null;
      }
      final rawExp = payload['exp'];
      final seconds = rawExp is int
          ? rawExp
          : rawExp is num
              ? rawExp.toInt()
              : int.tryParse(rawExp?.toString() ?? '');
      if (seconds == null) {
        return null;
      }
      return DateTime.fromMillisecondsSinceEpoch(seconds * 1000, isUtc: true)
          .toLocal();
    } catch (_) {
      return null;
    }
  }
}
