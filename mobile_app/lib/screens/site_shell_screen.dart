import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';

import '../config/app_config.dart';

class SiteShellScreen extends StatefulWidget {
  const SiteShellScreen({super.key});

  @override
  State<SiteShellScreen> createState() => _SiteShellScreenState();
}

class _SiteShellScreenState extends State<SiteShellScreen> {
  late final WebViewController _controller;
  int _loadingProgress = 0;
  bool _canGoBack = false;

  @override
  void initState() {
    super.initState();
    _controller = WebViewController()
      ..setJavaScriptMode(JavaScriptMode.unrestricted)
      ..setNavigationDelegate(
        NavigationDelegate(
          onProgress: (progress) {
            if (!mounted) {
              return;
            }
            setState(() {
              _loadingProgress = progress;
            });
          },
          onPageFinished: (_) => _syncCanGoBack(),
          onUrlChange: (_) => _syncCanGoBack(),
        ),
      )
      ..loadRequest(Uri.parse(AppConfig.siteUrl));
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

  @override
  Widget build(BuildContext context) {
    return PopScope(
      canPop: !_canGoBack,
      onPopInvokedWithResult: (didPop, _) async {
        if (didPop) {
          return;
        }
        await _controller.goBack();
        await _syncCanGoBack();
      },
      child: Scaffold(
        body: Stack(
          children: [
            WebViewWidget(controller: _controller),
            if (_loadingProgress < 100)
              SafeArea(
                child: LinearProgressIndicator(
                  value: _loadingProgress == 0 ? null : _loadingProgress / 100,
                ),
              ),
          ],
        ),
      ),
    );
  }
}
