import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:webview_flutter/webview_flutter.dart';

import '../config/app_config.dart';
import '../config/brand_config.dart';
import '../services/push_service.dart';

class SiteShellScreen extends StatefulWidget {
  SiteShellScreen({
    super.key,
    Uri? initialUri,
    this.pageTitle,
  }) : initialUri = initialUri ?? AppConfig.siteUri;

  factory SiteShellScreen.relativePath(
    String path, {
    Key? key,
    String? pageTitle,
  }) {
    return SiteShellScreen(
      key: key,
      initialUri: AppConfig.siteUri.resolve(path),
      pageTitle: pageTitle,
    );
  }

  final Uri initialUri;
  final String? pageTitle;

  @override
  State<SiteShellScreen> createState() => _SiteShellScreenState();
}

class _SiteShellScreenState extends State<SiteShellScreen> {
  late final WebViewController _controller;
  final PushService _pushService = PushService();
  int _loadingProgress = 0;
  bool _canGoBack = false;
  bool _hasRenderedFirstPage = false;
  bool _pushSyncInProgress = false;
  String? _loadError;
  DateTime? _lastExitAttemptAt;
  Uri _currentUri = AppConfig.siteUri;
  PushRegistration? _pushRegistration;
  String? _lastPushSyncSignature;

  @override
  void initState() {
    super.initState();
    _currentUri = widget.initialUri;
    _controller = WebViewController()
      ..setJavaScriptMode(JavaScriptMode.unrestricted)
      ..setNavigationDelegate(
        NavigationDelegate(
          onNavigationRequest: _handleNavigationRequest,
          onPageStarted: (url) {
            _updateCurrentUri(url);
            if (!mounted) {
              return;
            }
            setState(() {
              _loadingProgress = 0;
              _loadError = null;
            });
          },
          onProgress: (progress) {
            if (!mounted) {
              return;
            }
            setState(() {
              _loadingProgress = progress;
            });
          },
          onPageFinished: (url) async {
            _updateCurrentUri(url);
            await _syncCanGoBack();
            await _syncPushRegistrationWithSite();
            if (!mounted) {
              return;
            }
            setState(() {
              _loadingProgress = 100;
              _hasRenderedFirstPage = true;
              _loadError = null;
            });
          },
          onUrlChange: (change) {
            _updateCurrentUri(change.url);
            _syncCanGoBack();
          },
          onWebResourceError: (error) {
            if (!mounted || error.isForMainFrame == false) {
              return;
            }
            final description = error.description.trim();
            if (_hasRenderedFirstPage) {
              _showSnackBar(
                description.isEmpty
                    ? 'Sayfa yüklenirken bir bağlantı hatası oluştu.'
                    : description,
              );
              return;
            }
            setState(() {
              _loadError = description.isEmpty
                  ? 'Siteye ulaşılamadı. Bağlantını kontrol edip yeniden dene.'
                  : description;
            });
          },
        ),
      );
    _bootstrapController();
    _bootstrapPushBridge();
  }

  Future<void> _bootstrapController() async {
    await _controller.setUserAgent(AppConfig.userAgent);
    await _controller.loadRequest(widget.initialUri);
  }

  Future<void> _bootstrapPushBridge() async {
    final registration = await _pushService.initialize(
      onRegistrationChanged: (registration) async {
        _pushRegistration = registration;
        await _syncPushRegistrationWithSite(force: true);
      },
    );
    if (registration != null) {
      _pushRegistration = registration;
      await _syncPushRegistrationWithSite(force: true);
    }
  }

  Future<NavigationDecision> _handleNavigationRequest(
    NavigationRequest request,
  ) async {
    final uri = Uri.tryParse(request.url.trim());
    if (uri == null || _shouldStayInsideWebView(uri)) {
      return NavigationDecision.navigate;
    }

    final didLaunch = await _openExternally(
      uri,
      failureMessage: 'Bağlantı cihazda açılamadı.',
    );
    return didLaunch ? NavigationDecision.prevent : NavigationDecision.navigate;
  }

  bool _shouldStayInsideWebView(Uri uri) {
    final scheme = uri.scheme.toLowerCase();
    if (scheme == 'http' || scheme == 'https') {
      return _isInternalHttpUri(uri);
    }
    return switch (scheme) {
      'about' || 'javascript' || 'data' || 'blob' || 'file' => true,
      _ => false,
    };
  }

  bool _isInternalHttpUri(Uri uri) {
    final host = uri.host.toLowerCase();
    final appHost = AppConfig.siteUri.host.toLowerCase();

    if (host.isEmpty || appHost.isEmpty) {
      return true;
    }

    return host == appHost || host.endsWith('.$appHost');
  }

  void _updateCurrentUri(String? url) {
    final parsed = url == null ? null : Uri.tryParse(url);
    if (parsed == null) {
      return;
    }
    _currentUri = parsed;
  }

  Future<void> _syncPushRegistrationWithSite({bool force = false}) async {
    if (_pushSyncInProgress || _pushRegistration == null) {
      return;
    }
    if (!_isInternalHttpUri(_currentUri)) {
      return;
    }

    _pushSyncInProgress = true;
    try {
      final contextPayload = await _runJsonRequest(
        '''
        async function () {
          const response = await fetch('/api/mobile-shell/context/', {
            credentials: 'include',
            cache: 'no-store'
          });
          return await response.json();
        }
        ''',
      );
      if (contextPayload == null) {
        return;
      }

      final isAuthenticated = contextPayload['authenticated'] == true;
      if (!isAuthenticated) {
        if (_lastPushSyncSignature != null) {
          await _postPushPayload(
            '/api/mobile-shell/devices/unregister/',
            _pushRegistration!.toJson(),
          );
          _lastPushSyncSignature = null;
        }
        return;
      }

      final userId = (contextPayload['user_id'] ?? '').toString();
      if (userId.isEmpty) {
        return;
      }
      final nextSignature = '$userId|${_pushRegistration!.pushToken}';
      if (!force && _lastPushSyncSignature == nextSignature) {
        return;
      }

      final registerPayload = await _postPushPayload(
        '/api/mobile-shell/devices/register/',
        _pushRegistration!.toJson(),
      );
      if (registerPayload != null && registerPayload['ok'] == true) {
        _lastPushSyncSignature = nextSignature;
      }
    } finally {
      _pushSyncInProgress = false;
    }
  }

  Future<Map<String, dynamic>?> _postPushPayload(
    String path,
    Map<String, dynamic> payload,
  ) async {
    final jsonPayload = jsonEncode(payload);
    return _runJsonRequest(
      '''
      async function () {
        const response = await fetch('$path', {
          method: 'POST',
          credentials: 'include',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify($jsonPayload)
        });
        const text = await response.text();
        let body = {};
        try {
          body = text ? JSON.parse(text) : {};
        } catch (_) {
          body = {};
        }
        return {
          ok: response.ok,
          status: response.status,
          body: body
        };
      }
      ''',
    );
  }

  Future<Map<String, dynamic>?> _runJsonRequest(
      String asyncFunctionSource) async {
    try {
      final rawResult = await _controller.runJavaScriptReturningResult(
        '''
        (async () => {
          try {
            const payload = await ($asyncFunctionSource)();
            return JSON.stringify(payload);
          } catch (error) {
            return JSON.stringify({
              ok: false,
              error: String(error)
            });
          }
        })();
        ''',
      );
      return _decodeJavaScriptMap(rawResult);
    } catch (_) {
      return null;
    }
  }

  Map<String, dynamic>? _decodeJavaScriptMap(Object? rawResult) {
    if (rawResult == null) {
      return null;
    }

    String text = rawResult.toString().trim();
    if (text.startsWith('"') && text.endsWith('"')) {
      text = text.substring(1, text.length - 1);
      text = text.replaceAll(r'\"', '"').replaceAll(r'\n', '\n');
    }
    if (text.isEmpty) {
      return null;
    }

    final decoded = jsonDecode(text);
    if (decoded is Map<String, dynamic>) {
      return decoded;
    }
    if (decoded is Map) {
      return decoded.map((key, value) => MapEntry(key.toString(), value));
    }
    return null;
  }

  Future<bool> _openExternally(
    Uri uri, {
    required String failureMessage,
  }) async {
    try {
      final didLaunch = await launchUrl(
        uri,
        mode: LaunchMode.externalApplication,
      );
      if (!didLaunch) {
        _showSnackBar(failureMessage);
      }
      return didLaunch;
    } catch (_) {
      _showSnackBar(failureMessage);
      return false;
    }
  }

  void _showSnackBar(String message) {
    if (!mounted) {
      return;
    }
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(SnackBar(content: Text(message)));
  }

  Future<void> _syncCanGoBack() async {
    final canGoBack = await _controller.canGoBack();
    if (!mounted || canGoBack == _canGoBack) {
      return;
    }
    setState(() {
      _canGoBack = canGoBack;
    });
  }

  Future<void> _retryInitialLoad() async {
    if (!mounted) {
      return;
    }
    setState(() {
      _loadError = null;
      _loadingProgress = 0;
    });
    _currentUri = widget.initialUri;
    await _controller.loadRequest(widget.initialUri);
  }

  Future<void> _goToHome() async {
    HapticFeedback.selectionClick();
    if (!mounted) {
      return;
    }
    setState(() {
      _loadError = null;
      _loadingProgress = 0;
    });
    _currentUri = widget.initialUri;
    await _controller.loadRequest(widget.initialUri);
  }

  Future<void> _reloadPage() async {
    HapticFeedback.selectionClick();
    if (!mounted) {
      return;
    }
    setState(() {
      _loadingProgress = 0;
    });
    await _controller.reload();
  }

  Future<void> _goBackPage() async {
    if (!_canGoBack) {
      return;
    }
    HapticFeedback.selectionClick();
    await _controller.goBack();
    await _syncCanGoBack();
  }

  Future<void> _openCurrentPageInBrowser() async {
    HapticFeedback.selectionClick();
    await _openExternally(
      _currentUri,
      failureMessage: 'Sayfa tarayıcıda açılamadı.',
    );
  }

  Future<void> _handleBackPressed() async {
    if (_canGoBack) {
      await _goBackPage();
      return;
    }

    final now = DateTime.now();
    final shouldExit = _lastExitAttemptAt != null &&
        now.difference(_lastExitAttemptAt!) < const Duration(seconds: 2);

    if (shouldExit) {
      await SystemNavigator.pop();
      return;
    }

    _lastExitAttemptAt = now;
    _showSnackBar('Uygulamadan çıkmak için tekrar geri bas.');
  }

  @override
  Widget build(BuildContext context) {
    final showInitialOverlay = !_hasRenderedFirstPage && _loadError == null;
    final showErrorOverlay = !_hasRenderedFirstPage && _loadError != null;
    final showQuickActions = _hasRenderedFirstPage && _loadError == null;

    return AnnotatedRegion<SystemUiOverlayStyle>(
      value: BrandConfig.overlayStyleFor(Theme.of(context).brightness),
      child: PopScope(
        canPop: false,
        onPopInvokedWithResult: (didPop, _) async {
          if (didPop) {
            return;
          }
          await _handleBackPressed();
        },
        child: Scaffold(
          appBar: widget.pageTitle == null
              ? null
              : AppBar(
                  title: Text(widget.pageTitle!),
                  backgroundColor: BrandConfig.backgroundOf(context),
                ),
          backgroundColor: BrandConfig.backgroundOf(context),
          body: Stack(
            children: [
              WebViewWidget(controller: _controller),
              if (showInitialOverlay)
                AnimatedOpacity(
                  opacity: showInitialOverlay ? 1 : 0,
                  duration: const Duration(milliseconds: 280),
                  child: IgnorePointer(
                    ignoring: !showInitialOverlay,
                    child: _LaunchOverlay(progress: _loadingProgress),
                  ),
                ),
              if (showErrorOverlay)
                _ErrorOverlay(
                  message: _loadError!,
                  onRetry: _retryInitialLoad,
                ),
              if (_hasRenderedFirstPage && _loadingProgress < 100)
                const SafeArea(
                  child: Align(
                    alignment: Alignment.topCenter,
                    child: SizedBox(
                      width: double.infinity,
                      child: LinearProgressIndicator(minHeight: 2),
                    ),
                  ),
                ),
              if (showQuickActions)
                SafeArea(
                  child: Align(
                    alignment: Alignment.bottomCenter,
                    child: Padding(
                      padding: const EdgeInsets.fromLTRB(16, 16, 16, 18),
                      child: _QuickActionsBar(
                        canGoBack: _canGoBack,
                        onBack: _goBackPage,
                        onHome: _goToHome,
                        onRefresh: _reloadPage,
                        onOpenInBrowser: _openCurrentPageInBrowser,
                      ),
                    ),
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }

  @override
  void dispose() {
    _pushService.dispose();
    super.dispose();
  }
}

class _QuickActionsBar extends StatelessWidget {
  const _QuickActionsBar({
    required this.canGoBack,
    required this.onBack,
    required this.onHome,
    required this.onRefresh,
    required this.onOpenInBrowser,
  });

  final bool canGoBack;
  final Future<void> Function() onBack;
  final Future<void> Function() onHome;
  final Future<void> Function() onRefresh;
  final Future<void> Function() onOpenInBrowser;

  @override
  Widget build(BuildContext context) {
    return DecoratedBox(
      decoration: BoxDecoration(
        color: BrandConfig.floatingSurfaceOf(context),
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: BrandConfig.accentSoftOf(context)),
        boxShadow: [
          BoxShadow(
            color: BrandConfig.floatingShadowOf(context),
            blurRadius: 18,
            offset: Offset(0, 10),
          ),
        ],
      ),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 6),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            _QuickActionButton(
              icon: Icons.arrow_back_rounded,
              tooltip: 'Geri',
              onPressed: canGoBack
                  ? () {
                      onBack();
                    }
                  : null,
            ),
            _QuickActionButton(
              icon: Icons.home_rounded,
              tooltip: 'Ana sayfa',
              onPressed: () {
                onHome();
              },
            ),
            _QuickActionButton(
              icon: Icons.refresh_rounded,
              tooltip: 'Yenile',
              onPressed: () {
                onRefresh();
              },
            ),
            _QuickActionButton(
              icon: Icons.open_in_browser_rounded,
              tooltip: 'Tarayıcıda aç',
              onPressed: () {
                onOpenInBrowser();
              },
            ),
          ],
        ),
      ),
    );
  }
}

class _QuickActionButton extends StatelessWidget {
  const _QuickActionButton({
    required this.icon,
    required this.tooltip,
    required this.onPressed,
  });

  final IconData icon;
  final String tooltip;
  final VoidCallback? onPressed;

  @override
  Widget build(BuildContext context) {
    final isEnabled = onPressed != null;

    return IconButton(
      onPressed: onPressed,
      tooltip: tooltip,
      visualDensity: VisualDensity.compact,
      style: IconButton.styleFrom(
        foregroundColor: isEnabled
            ? BrandConfig.textOf(context)
            : BrandConfig.textMutedOf(context).withValues(alpha: 0.45),
      ),
      icon: Icon(icon),
    );
  }
}

class _ErrorOverlay extends StatelessWidget {
  const _ErrorOverlay({
    required this.message,
    required this.onRetry,
  });

  final String message;
  final Future<void> Function() onRetry;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return ColoredBox(
      color: BrandConfig.backgroundOf(context),
      child: SafeArea(
        child: Center(
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 28),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                ClipRRect(
                  borderRadius: BorderRadius.circular(28),
                  child: Image.asset(
                    'assets/branding/app_icon.png',
                    width: 108,
                    height: 108,
                    fit: BoxFit.cover,
                  ),
                ),
                const SizedBox(height: 22),
                Text(
                  'Bağlantı Sorunu',
                  style: theme.textTheme.headlineSmall?.copyWith(
                    color: BrandConfig.textOf(context),
                    fontWeight: FontWeight.w800,
                  ),
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 10),
                Text(
                  message,
                  style: theme.textTheme.bodyMedium?.copyWith(
                    color: BrandConfig.textMutedOf(context),
                    height: 1.45,
                  ),
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 20),
                FilledButton.icon(
                  onPressed: () {
                    onRetry();
                  },
                  icon: const Icon(Icons.refresh_rounded),
                  label: const Text('Yeniden Dene'),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _LaunchOverlay extends StatelessWidget {
  const _LaunchOverlay({required this.progress});

  final int progress;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final double? value = progress == 0 ? null : progress / 100;

    return ColoredBox(
      color: BrandConfig.backgroundOf(context),
      child: SafeArea(
        child: Center(
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 28),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                ClipRRect(
                  borderRadius: BorderRadius.circular(28),
                  child: Image.asset(
                    'assets/branding/app_icon.png',
                    width: 108,
                    height: 108,
                    fit: BoxFit.cover,
                  ),
                ),
                const SizedBox(height: 22),
                Text(
                  'UstaBul',
                  style: theme.textTheme.headlineMedium?.copyWith(
                    color: BrandConfig.textOf(context),
                    fontWeight: FontWeight.w800,
                    letterSpacing: -0.8,
                  ),
                ),
                const SizedBox(height: 8),
                Text(
                  'Uygulama yükleniyor',
                  style: theme.textTheme.bodyMedium?.copyWith(
                    color: BrandConfig.textMutedOf(context),
                  ),
                ),
                const SizedBox(height: 20),
                ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 220),
                  child: ClipRRect(
                    borderRadius: BorderRadius.circular(999),
                    child: LinearProgressIndicator(
                      value: value,
                      minHeight: 6,
                      backgroundColor: BrandConfig.surfaceOf(context),
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
