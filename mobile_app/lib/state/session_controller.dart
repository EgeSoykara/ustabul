import 'package:flutter/foundation.dart';

import '../models/auth_session.dart';
import '../services/api_client.dart';
import '../services/auth_service.dart';
import '../services/auth_storage.dart';
import '../services/push_service.dart';
import '../services/web_auth_service.dart';

class SessionController extends ChangeNotifier {
  SessionController({
    required AuthService authService,
    required AuthStorage authStorage,
    required PushService pushService,
    required WebAuthService webAuthService,
  })  : _authService = authService,
        _authStorage = authStorage,
        _pushService = pushService,
        _webAuthService = webAuthService;

  final AuthService _authService;
  final AuthStorage _authStorage;
  final PushService _pushService;
  final WebAuthService _webAuthService;

  AuthSession? _session;
  bool _initializing = true;
  bool _loading = false;
  String? _error;

  AuthSession? get session => _session;
  bool get isInitializing => _initializing;
  bool get isLoading => _loading;
  String? get error => _error;
  bool get isAuthenticated => _session != null;

  Future<void> initialize() async {
    _initializing = true;
    _error = null;
    notifyListeners();

    final stored = await _authStorage.loadSession();
    if (stored == null) {
      _session = null;
      _initializing = false;
      notifyListeners();
      return;
    }

    try {
      await _webAuthService.restoreSession();
      final mePayload = await _authService.fetchMe(stored.accessToken);
      final userData = mePayload['user'];
      if (userData is! Map<String, dynamic>) {
        throw const ApiException('Profil verisi okunamadı.');
      }
      final snapshotData = mePayload['snapshot'];
      _session = stored.copyWith(
        role: (userData['role'] ?? '').toString(),
        user: userData,
        snapshot: snapshotData is Map<String, dynamic>
            ? snapshotData
            : <String, dynamic>{},
      );
      await _authStorage.saveSession(_session!);
      await _pushService.initializeAndRegister(_session!);
    } catch (_) {
      _session = null;
      await _authStorage.clear();
    } finally {
      _initializing = false;
      notifyListeners();
    }
  }

  Future<bool> login({
    required String username,
    required String password,
  }) async {
    _loading = true;
    _error = null;
    notifyListeners();
    try {
      final nextSession =
          await _authService.login(username: username, password: password);
      _session = nextSession;
      await _authStorage.saveSession(nextSession);
      await _pushService.initializeAndRegister(nextSession);
      try {
        await _webAuthService.login(
          username: username,
          password: password,
          isProvider: nextSession.isProvider,
        );
      } catch (_) {
        // Native mobile endpoints can still work even if the web session
        // handoff is temporarily unavailable.
      }
      return true;
    } catch (error) {
      _error = error.toString();
      return false;
    } finally {
      _loading = false;
      notifyListeners();
    }
  }

  Future<void> logout() async {
    _session = null;
    _error = null;
    await _authStorage.clear();
    await _webAuthService.clear();
    await _pushService.dispose();
    notifyListeners();
  }

  Future<bool> ensureWebSession() async {
    return _webAuthService.ensureSessionAvailable();
  }

  Future<String> ensureAccessToken() async {
    final current = _session;
    if (current == null) {
      throw const ApiException('Oturum bulunamadı.');
    }
    try {
      await _authService.fetchMe(current.accessToken);
      return current.accessToken;
    } catch (_) {
      final refreshed =
          await _authService.refreshAccessToken(current.refreshToken);
      _session = current.copyWith(accessToken: refreshed);
      await _authStorage.saveSession(_session!);
      return refreshed;
    }
  }

  Future<AuthSession> refreshProfile() async {
    final current = _session;
    if (current == null) {
      throw const ApiException('Oturum bulunamadı.');
    }
    final accessToken = await ensureAccessToken();
    final payload = await _authService.fetchMe(accessToken);
    final userData = payload['user'];
    if (userData is! Map<String, dynamic>) {
      throw const ApiException('Profil verisi okunamadı.');
    }
    final snapshotData = payload['snapshot'];
    _session = current.copyWith(
      accessToken: accessToken,
      role: (userData['role'] ?? '').toString(),
      user: userData,
      snapshot: snapshotData is Map<String, dynamic>
          ? snapshotData
          : <String, dynamic>{},
    );
    await _authStorage.saveSession(_session!);
    notifyListeners();
    return _session!;
  }

  @override
  void dispose() {
    _pushService.dispose();
    super.dispose();
  }
}
