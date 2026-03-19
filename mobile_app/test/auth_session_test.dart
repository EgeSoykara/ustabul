import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:ustabul_mobile/models/auth_session.dart';

void main() {
  group('AuthSession', () {
    test('extracts access token expiry from jwt payload', () {
      final expiresAt = DateTime.now().add(const Duration(minutes: 30));
      final session = AuthSession.fromJson({
        'access_token': _buildJwt(expiresAt),
        'refresh_token': 'refresh-token',
        'role': 'customer',
        'user': const {'role': 'customer'},
        'snapshot': const {},
      });

      expect(session.accessTokenExpiresAt, isNotNull);
      expect(
        session.accessTokenExpiresAt!.difference(expiresAt).inSeconds.abs(),
        lessThanOrEqualTo(1),
      );
    });

    test('shouldRefreshAccessToken becomes true close to expiry', () {
      final expiresSoon = DateTime.now().add(const Duration(seconds: 30));
      final session = AuthSession.fromJson({
        'access_token': _buildJwt(expiresSoon),
        'refresh_token': 'refresh-token',
        'role': 'customer',
        'user': const {'role': 'customer'},
        'snapshot': const {},
      });

      expect(session.shouldRefreshAccessToken(), isTrue);
    });
  });
}

String _buildJwt(DateTime expiresAt) {
  final header = base64Url.encode(utf8.encode('{"alg":"none","typ":"JWT"}'));
  final payload = base64Url.encode(
    utf8.encode(
      jsonEncode({
        'exp': expiresAt.toUtc().millisecondsSinceEpoch ~/ 1000,
      }),
    ),
  );
  return '$header.$payload.signature';
}
