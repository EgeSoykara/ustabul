import 'dart:async';
import 'dart:convert';
import 'dart:io';

typedef AccessTokenProvider = Future<String> Function();

class RealtimeUpdatesService {
  RealtimeUpdatesService({required String siteUrl})
      : _siteUri = Uri.parse(siteUrl);

  final Uri _siteUri;
  final StreamController<Map<String, dynamic>> _eventsController =
      StreamController<Map<String, dynamic>>.broadcast();

  Stream<Map<String, dynamic>> get events => _eventsController.stream;

  AccessTokenProvider? _tokenProvider;
  WebSocket? _socket;
  StreamSubscription<dynamic>? _socketSubscription;
  Timer? _reconnectTimer;
  bool _connecting = false;
  bool _manualStop = true;
  bool _disposed = false;
  int _reconnectAttempt = 0;

  Future<void> start({
    required AccessTokenProvider tokenProvider,
  }) async {
    _tokenProvider = tokenProvider;
    _manualStop = false;
    await _connectIfNeeded();
  }

  Future<void> stop() async {
    _manualStop = true;
    _reconnectAttempt = 0;
    _reconnectTimer?.cancel();
    _reconnectTimer = null;
    await _closeSocket();
  }

  void dispose() {
    _disposed = true;
    unawaited(stop());
    unawaited(_eventsController.close());
  }

  Uri _buildSocketUri(String accessToken) {
    final socketScheme = _siteUri.scheme == 'https' ? 'wss' : 'ws';
    return _siteUri.replace(
      scheme: socketScheme,
      path: '/ws/mobile/live/',
      queryParameters: {'token': accessToken},
    );
  }

  Future<void> _connectIfNeeded() async {
    if (_disposed ||
        _manualStop ||
        _connecting ||
        _socket != null ||
        _tokenProvider == null) {
      return;
    }

    _connecting = true;
    try {
      final accessToken = await _tokenProvider!();
      if (accessToken.isEmpty) {
        _scheduleReconnect();
        return;
      }
      final socketUri = _buildSocketUri(accessToken);
      final socket = await WebSocket.connect(
        socketUri.toString(),
        headers: {'Authorization': 'Bearer $accessToken'},
      );
      socket.pingInterval = const Duration(seconds: 20);
      _socket = socket;
      _reconnectAttempt = 0;
      _socketSubscription = socket.listen(
        _handleSocketData,
        onError: (_) => _handleSocketDisconnect(),
        onDone: _handleSocketDisconnect,
        cancelOnError: true,
      );
    } catch (_) {
      _scheduleReconnect();
    } finally {
      _connecting = false;
    }
  }

  void _handleSocketData(dynamic rawMessage) {
    if (_disposed) {
      return;
    }
    try {
      final decoded = jsonDecode(rawMessage.toString());
      if (decoded is Map<String, dynamic>) {
        _eventsController.add(decoded);
      }
    } catch (_) {
      // Ignore malformed payloads and keep the socket alive.
    }
  }

  void _handleSocketDisconnect() {
    unawaited(_closeSocket().then((_) => _scheduleReconnect()));
  }

  void _scheduleReconnect() {
    if (_disposed || _manualStop || _reconnectTimer != null) {
      return;
    }
    final delay = switch (_reconnectAttempt) {
      0 => const Duration(seconds: 2),
      1 => const Duration(seconds: 4),
      _ => const Duration(seconds: 6),
    };
    _reconnectAttempt += 1;
    _reconnectTimer = Timer(delay, () {
      _reconnectTimer = null;
      unawaited(_connectIfNeeded());
    });
  }

  Future<void> _closeSocket() async {
    await _socketSubscription?.cancel();
    _socketSubscription = null;
    final socket = _socket;
    _socket = null;
    if (socket != null) {
      try {
        await socket.close();
      } catch (_) {
        // Ignore close failures during reconnect or shutdown.
      }
    }
  }
}
