import 'dart:async';

import 'package:flutter/material.dart';

import '../config/brand_config.dart';
import '../services/mobile_data_service.dart';
import '../state/session_controller.dart';
import '../widgets/brand_backdrop.dart';

class RequestThreadScreen extends StatefulWidget {
  const RequestThreadScreen({
    super.key,
    required this.sessionController,
    required this.dataService,
    required this.requestId,
    required this.title,
    required this.subtitle,
  });

  final SessionController sessionController;
  final MobileDataService dataService;
  final int requestId;
  final String title;
  final String subtitle;

  @override
  State<RequestThreadScreen> createState() => _RequestThreadScreenState();
}

class _RequestThreadScreenState extends State<RequestThreadScreen> {
  final TextEditingController _composerController = TextEditingController();
  final ScrollController _scrollController = ScrollController();
  final List<Map<String, dynamic>> _messages = <Map<String, dynamic>>[];

  Timer? _pollTimer;
  bool _loading = true;
  bool _sending = false;
  String? _error;
  int _latestId = 0;

  @override
  void initState() {
    super.initState();
    _loadInitialMessages();
    _pollTimer = Timer.periodic(
      const Duration(seconds: 5),
      (_) => _pollLatestMessages(),
    );
  }

  @override
  void dispose() {
    _pollTimer?.cancel();
    _composerController.dispose();
    _scrollController.dispose();
    super.dispose();
  }

  Future<void> _loadInitialMessages() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final accessToken = await widget.sessionController.ensureAccessToken();
      final payload = await widget.dataService.fetchRequestMessages(
        accessToken: accessToken,
        requestId: widget.requestId,
      );
      final nextMessages = _normalizeMessages(payload['messages']);
      if (!mounted) {
        return;
      }
      setState(() {
        _messages
          ..clear()
          ..addAll(nextMessages);
        _latestId = (payload['latest_id'] as num?)?.toInt() ?? 0;
      });
      _scrollToBottom(animated: false);
    } catch (error) {
      if (!mounted) {
        return;
      }
      setState(() {
        _error = error.toString();
      });
    } finally {
      if (mounted) {
        setState(() {
          _loading = false;
        });
      }
    }
  }

  Future<void> _pollLatestMessages() async {
    if (!mounted || _loading || _sending) {
      return;
    }
    try {
      final accessToken = await widget.sessionController.ensureAccessToken();
      final payload = await widget.dataService.fetchRequestMessages(
        accessToken: accessToken,
        requestId: widget.requestId,
        afterId: _latestId,
      );
      final nextMessages = _normalizeMessages(payload['messages']);
      if (!mounted || nextMessages.isEmpty) {
        return;
      }
      setState(() {
        _messages.addAll(nextMessages);
        _latestId = (payload['latest_id'] as num?)?.toInt() ?? _latestId;
        _error = null;
      });
      _scrollToBottom();
    } catch (_) {
      // Keep polling best-effort so brief network issues do not break the thread UI.
    }
  }

  Future<void> _sendMessage() async {
    final body = _composerController.text.trim();
    if (body.length < 2) {
      return;
    }
    setState(() {
      _sending = true;
      _error = null;
    });
    try {
      final accessToken = await widget.sessionController.ensureAccessToken();
      final payload = await widget.dataService.sendRequestMessage(
        accessToken: accessToken,
        requestId: widget.requestId,
        body: body,
      );
      final message = payload['message'];
      if (!mounted) {
        return;
      }
      _composerController.clear();
      if (message is Map<String, dynamic>) {
        setState(() {
          _messages.add(
            message.map(
              (key, value) => MapEntry(key.toString(), value),
            ),
          );
          _latestId = (message['id'] as num?)?.toInt() ?? _latestId;
        });
        _scrollToBottom();
      }
    } catch (error) {
      if (!mounted) {
        return;
      }
      setState(() {
        _error = error.toString();
      });
    } finally {
      if (mounted) {
        setState(() {
          _sending = false;
        });
      }
    }
  }

  List<Map<String, dynamic>> _normalizeMessages(dynamic rawMessages) {
    if (rawMessages is! List) {
      return const <Map<String, dynamic>>[];
    }
    return rawMessages
        .whereType<Map>()
        .map(
          (item) => item.map(
            (key, value) => MapEntry(key.toString(), value),
          ),
        )
        .toList();
  }

  void _scrollToBottom({bool animated = true}) {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!_scrollController.hasClients) {
        return;
      }
      final target = _scrollController.position.maxScrollExtent + 80;
      if (animated) {
        _scrollController.animateTo(
          target,
          duration: const Duration(milliseconds: 240),
          curve: Curves.easeOut,
        );
      } else {
        _scrollController.jumpTo(target);
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        titleSpacing: 0,
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(widget.title),
            Text(
              widget.subtitle,
              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                    color: BrandConfig.textMutedOf(context),
                  ),
            ),
          ],
        ),
      ),
      body: BrandBackdrop(
        child: Column(
          children: [
            if (_error != null)
              Container(
                width: double.infinity,
                color: BrandConfig.warningSurfaceOf(context),
                padding:
                    const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                child: Text(
                  _error!,
                  style: TextStyle(color: BrandConfig.textOf(context)),
                ),
              ),
            Expanded(
              child: RefreshIndicator(
                onRefresh: _loadInitialMessages,
                child: _loading
                    ? const Center(child: CircularProgressIndicator())
                    : _messages.isEmpty
                        ? ListView(
                            padding: const EdgeInsets.all(24),
                            children: const [
                              SizedBox(height: 120),
                              _EmptyThreadCard(),
                            ],
                          )
                        : ListView.builder(
                            controller: _scrollController,
                            padding: const EdgeInsets.fromLTRB(16, 18, 16, 16),
                            itemCount: _messages.length,
                            itemBuilder: (context, index) {
                              final message = _messages[index];
                              return _MessageBubble(
                                body: (message['body'] ?? '').toString(),
                                senderLabel:
                                    (message['sender_label'] ?? '').toString(),
                                createdAt:
                                    (message['created_at'] ?? '').toString(),
                                isMine: message['mine'] == true,
                              );
                            },
                          ),
              ),
            ),
            SafeArea(
              top: false,
              child: Padding(
                padding: const EdgeInsets.fromLTRB(16, 8, 16, 14),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.end,
                  children: [
                    Expanded(
                      child: TextField(
                        controller: _composerController,
                        minLines: 1,
                        maxLines: 4,
                        textInputAction: TextInputAction.newline,
                        decoration: const InputDecoration(
                          hintText: 'Mesajınızı yazın',
                        ),
                      ),
                    ),
                    const SizedBox(width: 12),
                    FilledButton(
                      onPressed: _sending ? null : _sendMessage,
                      style: FilledButton.styleFrom(
                        minimumSize: const Size(56, 56),
                        shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(18),
                        ),
                      ),
                      child: _sending
                          ? const SizedBox(
                              width: 18,
                              height: 18,
                              child: CircularProgressIndicator(strokeWidth: 2),
                            )
                          : const Icon(Icons.send_rounded),
                    ),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _MessageBubble extends StatelessWidget {
  const _MessageBubble({
    required this.body,
    required this.senderLabel,
    required this.createdAt,
    required this.isMine,
  });

  final String body;
  final String senderLabel;
  final String createdAt;
  final bool isMine;

  @override
  Widget build(BuildContext context) {
    final isLightTheme = BrandConfig.isLight(context);
    final bubbleColor = isMine
        ? const Color(0xFF0F5F73)
        : BrandConfig.surfaceOf(
            context,
          ).withValues(alpha: isLightTheme ? 0.96 : 0.92);
    final borderColor = isMine
        ? const Color(0x33000000)
        : BrandConfig.borderOf(
            context,
          ).withValues(alpha: isLightTheme ? 0.55 : 0.42);
    final bodyColor =
        isMine ? const Color(0xFFF8FAFC) : BrandConfig.textOf(context);
    final senderColor =
        isMine ? const Color(0xFFD7EEF4) : BrandConfig.accentOf(context);
    final metaColor =
        isMine ? const Color(0xFFCAE3EA) : BrandConfig.textMutedOf(context);
    final alignment = isMine ? Alignment.centerRight : Alignment.centerLeft;
    final radius = BorderRadius.only(
      topLeft: const Radius.circular(22),
      topRight: const Radius.circular(22),
      bottomLeft: Radius.circular(isMine ? 22 : 8),
      bottomRight: Radius.circular(isMine ? 8 : 22),
    );
    final resolvedSender = senderLabel.trim().isEmpty
        ? (isMine ? 'Siz' : 'Mesaj')
        : senderLabel.trim();
    final resolvedTime = createdAt.trim();

    return Align(
      alignment: alignment,
      child: Container(
        constraints: const BoxConstraints(maxWidth: 320),
        margin: const EdgeInsets.only(bottom: 12),
        padding: const EdgeInsets.fromLTRB(14, 12, 14, 12),
        decoration: BoxDecoration(
          color: bubbleColor,
          borderRadius: radius,
          border: Border.all(color: borderColor),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withValues(alpha: isMine ? 0.08 : 0.05),
              blurRadius: 14,
              offset: const Offset(0, 8),
            ),
          ],
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Flexible(
                  child: Text(
                    resolvedSender,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(
                      color: senderColor,
                      fontSize: 12,
                      fontWeight: FontWeight.w800,
                      letterSpacing: 0.1,
                    ),
                  ),
                ),
                if (resolvedTime.isNotEmpty) ...[
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      resolvedTime,
                      overflow: TextOverflow.ellipsis,
                      textAlign: TextAlign.end,
                      style: TextStyle(
                        color: metaColor,
                        fontSize: 11,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ),
                ],
              ],
            ),
            const SizedBox(height: 8),
            Text(
              body,
              style: TextStyle(
                color: bodyColor,
                height: 1.4,
                fontSize: 15,
                fontWeight: FontWeight.w600,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _EmptyThreadCard extends StatelessWidget {
  const _EmptyThreadCard();

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          children: [
            Icon(
              Icons.forum_outlined,
              size: 36,
              color: BrandConfig.textMutedOf(context),
            ),
            const SizedBox(height: 12),
            Text(
              'Henüz mesaj yok',
              style: Theme.of(context).textTheme.titleMedium?.copyWith(
                    fontWeight: FontWeight.w700,
                  ),
            ),
            const SizedBox(height: 8),
            Text(
              'İlk mesajı göndererek görüşmeyi buradan başlatabilirsiniz.',
              textAlign: TextAlign.center,
              style: TextStyle(color: BrandConfig.textMutedOf(context)),
            ),
          ],
        ),
      ),
    );
  }
}
