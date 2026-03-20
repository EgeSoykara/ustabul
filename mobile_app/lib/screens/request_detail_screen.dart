import 'dart:async';

import 'package:flutter/material.dart';

import '../config/brand_config.dart';
import '../services/api_client.dart';
import '../services/mobile_data_service.dart';
import '../state/session_controller.dart';
import '../widgets/brand_backdrop.dart';
import 'provider_detail_screen.dart';
import 'request_thread_screen.dart';
import 'site_shell_screen.dart';

class RequestDetailScreen extends StatefulWidget {
  const RequestDetailScreen({
    super.key,
    required this.sessionController,
    required this.dataService,
    required this.requestId,
  });

  final SessionController sessionController;
  final MobileDataService dataService;
  final int requestId;

  @override
  State<RequestDetailScreen> createState() => _RequestDetailScreenState();
}

class _RequestDetailScreenState extends State<RequestDetailScreen>
    with WidgetsBindingObserver {
  static const Duration _refreshTickInterval = Duration(seconds: 5);
  static const Duration _activeDetailRefreshInterval = Duration(seconds: 5);
  static const Duration _settledDetailRefreshInterval = Duration(seconds: 10);

  Timer? _autoRefreshTimer;
  Timer? _liveUpdateTimer;
  StreamSubscription<Map<String, dynamic>>? _liveUpdatesSubscription;
  bool _loading = true;
  bool _actionLoading = false;
  bool _requestInFlight = false;
  String? _error;
  Map<String, dynamic> _payload = const {};
  bool _isRatingEditorOpen = false;
  int _ratingDraftScore = 5;
  AppLifecycleState _appLifecycleState = AppLifecycleState.resumed;
  DateTime? _lastSyncAt;
  String _detailVersion = '';
  String? _liveUpdateMessage;
  final TextEditingController _ratingCommentController =
      TextEditingController();

  Map<String, dynamic> get _request =>
      _payload['request'] is Map<String, dynamic>
          ? _payload['request'] as Map<String, dynamic>
          : const <String, dynamic>{};

  Map<String, dynamic> get _actions =>
      _payload['actions'] is Map<String, dynamic>
          ? _payload['actions'] as Map<String, dynamic>
          : const <String, dynamic>{};

  Map<String, dynamic>? get _matchedProvider =>
      _payload['matched_provider'] is Map<String, dynamic>
          ? _payload['matched_provider'] as Map<String, dynamic>
          : null;

  Map<String, dynamic>? get _appointment =>
      _payload['appointment'] is Map<String, dynamic>
          ? _payload['appointment'] as Map<String, dynamic>
          : null;

  Map<String, dynamic>? get _providerOffer =>
      _payload['provider_offer'] is Map<String, dynamic>
          ? _payload['provider_offer'] as Map<String, dynamic>
          : null;

  Map<String, dynamic> get _flowState =>
      _payload['flow_state'] is Map<String, dynamic>
          ? _payload['flow_state'] as Map<String, dynamic>
          : const <String, dynamic>{};

  Map<String, dynamic>? get _rating =>
      _payload['rating'] is Map<String, dynamic>
          ? _payload['rating'] as Map<String, dynamic>
          : null;

  Map<String, dynamic> get _ratingState =>
      _payload['rating_state'] is Map<String, dynamic>
          ? _payload['rating_state'] as Map<String, dynamic>
          : const <String, dynamic>{};

  List<Map<String, dynamic>> get _acceptedOffers {
    final raw = _payload['accepted_offers'];
    if (raw is! List) {
      return const <Map<String, dynamic>>[];
    }
    return raw
        .whereType<Map>()
        .map(
            (item) => item.map((key, value) => MapEntry(key.toString(), value)))
        .toList();
  }

  bool get _isProviderViewer => (_payload['viewer_role'] ?? '') == 'provider';

  List<String> get _flowLabels {
    final calendarEnabled = _payload['calendar_enabled'] == true;
    if (_isProviderViewer) {
      return calendarEnabled
          ? const <String>[
              'Talep kararı',
              'Müşteri seçimi',
              'Eşleşme',
              'Randevu / Tamamlama',
            ]
          : const <String>[
              'Talep kararı',
              'Müşteri seçimi',
              'Tamamlama',
            ];
    }
    return calendarEnabled
        ? const <String>[
            'Talep gönderildi',
            'Usta seçimi',
            'Randevu',
            'Tamamlama',
          ]
        : const <String>[
            'Talep gönderildi',
            'Usta seçimi',
            'Tamamlama',
          ];
  }

  bool get _forceNativeProviderFlow =>
      widget.sessionController.session?.isProvider == true;

  String get _webFallbackPath {
    final session = widget.sessionController.session;
    if (session?.isProvider == true) {
      return '/usta/talepler/';
    }
    return '/taleplerim/';
  }

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _subscribeToLiveUpdates();
    _startAutoRefresh();
    _load();
  }

  @override
  void dispose() {
    _autoRefreshTimer?.cancel();
    _liveUpdateTimer?.cancel();
    _liveUpdatesSubscription?.cancel();
    WidgetsBinding.instance.removeObserver(this);
    _ratingCommentController.dispose();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    _appLifecycleState = state;
    if (state == AppLifecycleState.resumed) {
      _refreshSilently(force: true);
    }
  }

  void _startAutoRefresh() {
    _autoRefreshTimer?.cancel();
    _autoRefreshTimer = Timer.periodic(
      _refreshTickInterval,
      (_) => _refreshSilently(),
    );
  }

  void _subscribeToLiveUpdates() {
    _liveUpdatesSubscription?.cancel();
    _liveUpdatesSubscription = widget.sessionController.liveUpdates.listen(
      _handleLiveUpdateEvent,
    );
  }

  void _handleLiveUpdateEvent(Map<String, dynamic> event) {
    if (!mounted ||
        _actionLoading ||
        _appLifecycleState != AppLifecycleState.resumed ||
        !_isVisibleRoute()) {
      return;
    }
    if ((event['type'] ?? '').toString() != 'refresh.hint') {
      return;
    }
    final rawRequestId = event['request_id'];
    final requestId = rawRequestId is int
        ? rawRequestId
        : rawRequestId is num
            ? rawRequestId.toInt()
            : int.tryParse(rawRequestId?.toString() ?? '');
    if (requestId != widget.requestId) {
      return;
    }
    unawaited(_load(silent: true));
  }

  bool _isVisibleRoute() {
    if (!mounted) {
      return false;
    }
    final route = ModalRoute.of(context);
    return route?.isCurrent ?? true;
  }

  Duration _currentRefreshInterval() {
    final status = (_request['status'] ?? '').toString();
    if (status == 'completed' || status == 'cancelled') {
      return _settledDetailRefreshInterval;
    }
    return _activeDetailRefreshInterval;
  }

  bool _isRefreshDue() {
    if (_lastSyncAt == null) {
      return true;
    }
    return DateTime.now().difference(_lastSyncAt!) >= _currentRefreshInterval();
  }

  void _showLiveUpdateCue(String message) {
    if (!mounted) {
      return;
    }
    _liveUpdateTimer?.cancel();
    setState(() {
      _liveUpdateMessage = message;
    });
    _liveUpdateTimer = Timer(const Duration(seconds: 5), () {
      if (!mounted) {
        return;
      }
      setState(() {
        _liveUpdateMessage = null;
      });
    });
  }

  void _clearLiveUpdateCue() {
    _liveUpdateTimer?.cancel();
    if (!mounted) {
      return;
    }
    setState(() {
      _liveUpdateMessage = null;
    });
  }

  void _refreshSilently({bool force = false}) {
    if (!mounted ||
        _actionLoading ||
        _appLifecycleState != AppLifecycleState.resumed ||
        !_isVisibleRoute()) {
      return;
    }
    if (force || _isRefreshDue()) {
      unawaited(_load(silent: true));
    }
  }

  Future<void> _openWebFallback() async {
    final ready = await widget.sessionController.ensureWebSession();
    if (!mounted) {
      return;
    }
    if (!ready) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text(
            'Site görünümü için tekrar giriş yapmanız gerekebilir.',
          ),
        ),
      );
    }
    await Navigator.of(context).pushReplacement(
      MaterialPageRoute<void>(
        builder: (_) => SiteShellScreen.relativePath(
          _webFallbackPath,
          pageTitle: 'UstaBul',
        ),
      ),
    );
  }

  Future<void> _handleMissingNativeEndpoint({bool duringAction = false}) async {
    if (!_forceNativeProviderFlow) {
      await _openWebFallback();
      return;
    }
    if (!mounted) {
      return;
    }
    const message =
        'Bu usta işlemi için gereken mobil endpoint canlı backend tarafında henüz yayınlanmamış. Web görünümüne yönlendirme kapalı tutuldu.';
    setState(() {
      _error = message;
    });
    if (duringAction) {
      ScaffoldMessenger.of(context)
        ..hideCurrentSnackBar()
        ..showSnackBar(const SnackBar(content: Text(message)));
    }
  }

  Future<void> _load({bool silent = false}) async {
    if (_requestInFlight) {
      return;
    }
    _requestInFlight = true;
    if (!silent) {
      _clearLiveUpdateCue();
    }
    if (!silent) {
      setState(() {
        _loading = true;
        _error = null;
      });
    }
    try {
      final accessToken = await widget.sessionController.ensureAccessToken();
      if (silent) {
        final summary = await widget.dataService.fetchRequestDetailSummary(
          accessToken: accessToken,
          requestId: widget.requestId,
        );
        final nextVersion = (summary['version'] ?? '').toString();
        final changed =
            _detailVersion.isNotEmpty && nextVersion != _detailVersion;
        _detailVersion = nextVersion;
        _lastSyncAt = DateTime.now();
        if (!changed) {
          return;
        }
      }
      final payload = await widget.dataService.fetchRequestDetail(
        accessToken: accessToken,
        requestId: widget.requestId,
      );
      final nextVersion = (payload['version'] ?? '').toString();
      final changed =
          _detailVersion.isNotEmpty && nextVersion != _detailVersion;
      if (!mounted) {
        return;
      }
      setState(() {
        _payload = payload;
        _error = null;
        _detailVersion = nextVersion;
        if (!_isRatingEditorOpen) {
          _syncRatingDraftFromPayload();
        }
      });
      if (silent && changed) {
        _showLiveUpdateCue('Talepte yeni bir gelişme algılandı');
      }
      _lastSyncAt = DateTime.now();
    } catch (error) {
      if (error is ApiException && error.statusCode == 404) {
        if (silent) {
          return;
        }
        await _handleMissingNativeEndpoint();
        return;
      }
      if (!mounted || silent) {
        return;
      }
      setState(() {
        _error = error.toString();
      });
    } finally {
      _requestInFlight = false;
      if (mounted && !silent) {
        setState(() {
          _loading = false;
        });
      }
    }
  }

  Future<void> _performAndPop(
      Future<Map<String, dynamic>> Function() action) async {
    var didPop = false;
    setState(() {
      _actionLoading = true;
      _error = null;
    });
    try {
      final payload = await action();
      if (!mounted) {
        return;
      }
      final message = (payload['message'] ?? 'İşlem tamamlandı.').toString();
      ScaffoldMessenger.of(context)
        ..hideCurrentSnackBar()
        ..showSnackBar(SnackBar(content: Text(message)));
      didPop = true;
      Navigator.of(context).pop(true);
      return;
    } catch (error) {
      if (error is ApiException && error.statusCode == 404) {
        await _handleMissingNativeEndpoint(duringAction: true);
        return;
      }
      if (!mounted) {
        return;
      }
      setState(() {
        _error = error.toString();
      });
    } finally {
      if (mounted && !didPop) {
        setState(() {
          _actionLoading = false;
        });
      }
    }
  }

  // ignore: unused_element
  Future<void> _performAndReload(
      Future<Map<String, dynamic>> Function() action) async {
    setState(() {
      _actionLoading = true;
      _error = null;
    });
    try {
      final payload = await action();
      if (!mounted) {
        return;
      }
      final message = (payload['message'] ?? 'İşlem tamamlandı.').toString();
      ScaffoldMessenger.of(context)
        ..hideCurrentSnackBar()
        ..showSnackBar(SnackBar(content: Text(message)));
      await _load();
    } catch (error) {
      if (error is ApiException && error.statusCode == 404) {
        await _handleMissingNativeEndpoint(duringAction: true);
        return;
      }
      if (!mounted) {
        return;
      }
      setState(() {
        _error = error.toString();
      });
    } finally {
      if (mounted) {
        setState(() {
          _actionLoading = false;
        });
      }
    }
  }

  Future<void> _submitRating(Map<String, dynamic> ratingInput) async {
    setState(() {
      _actionLoading = true;
      _error = null;
    });
    try {
      final accessToken = await widget.sessionController.ensureAccessToken();
      final payload = await widget.dataService.submitRequestRating(
        accessToken: accessToken,
        requestId: widget.requestId,
        score: (ratingInput['score'] as num?)?.toInt() ?? 5,
        comment: (ratingInput['comment'] ?? '').toString(),
      );
      if (!mounted) {
        return;
      }
      final message = (payload['message'] ?? 'Puan kaydedildi.').toString();
      setState(() {
        _payload = {
          ..._payload,
          if (payload['rating'] is Map<String, dynamic>)
            'rating': payload['rating'] as Map<String, dynamic>,
          if (payload['rating_state'] is Map<String, dynamic>)
            'rating_state': payload['rating_state'] as Map<String, dynamic>,
          'actions': {
            ..._actions,
            if (payload['rating_state'] is Map<String, dynamic>)
              'can_rate': (payload['rating_state']
                      as Map<String, dynamic>)['can_rate'] ==
                  true,
          },
        };
        _isRatingEditorOpen = false;
        _syncRatingDraftFromPayload();
      });
      ScaffoldMessenger.of(context)
        ..hideCurrentSnackBar()
        ..showSnackBar(SnackBar(content: Text(message)));
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
          _actionLoading = false;
        });
      }
    }
  }

  void _syncRatingDraftFromPayload() {
    _ratingDraftScore = ((_rating?['score'] as num?)?.toInt() ?? 5).clamp(1, 5);
    _ratingCommentController.text = (_rating?['comment'] ?? '').toString();
  }

  void _openRatingEditor() {
    setState(() {
      _isRatingEditorOpen = true;
      _syncRatingDraftFromPayload();
    });
  }

  void _closeRatingEditor() {
    setState(() {
      _isRatingEditorOpen = false;
      _syncRatingDraftFromPayload();
    });
  }

  Future<String?> _promptForShortNote({
    required String title,
    required String hintText,
  }) async {
    var draft = '';
    final result = await showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: BrandConfig.surfaceOf(context),
        title: Text(title),
        content: TextFormField(
          autofocus: true,
          maxLength:
              ((_payload['short_note_max_length'] as num?)?.toInt() ?? 100),
          minLines: 1,
          maxLines: 3,
          decoration: InputDecoration(hintText: hintText),
          onChanged: (value) {
            draft = value;
          },
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Vazgeç'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(draft.trim()),
            child: const Text('Devam et'),
          ),
        ],
      ),
    );
    return result;
  }

  // ignore: unused_element
  Future<Map<String, dynamic>?> _promptForRating() async {
    var selectedScore = ((_rating?['score'] as num?)?.toInt() ?? 5).clamp(1, 5);
    var commentDraft = (_rating?['comment'] ?? '').toString();
    final result = await showDialog<Map<String, dynamic>>(
      context: context,
      builder: (context) => StatefulBuilder(
        builder: (context, setModalState) => AlertDialog(
          backgroundColor: BrandConfig.surfaceOf(context),
          title: Text(_rating == null ? 'Ustayı puanla' : 'Puanını güncelle'),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Puan',
                  style: Theme.of(context).textTheme.titleSmall?.copyWith(
                        fontWeight: FontWeight.w800,
                      ),
                ),
                const SizedBox(height: 10),
                Row(
                  children: List<Widget>.generate(5, (index) {
                    final score = index + 1;
                    final active = score <= selectedScore;
                    return IconButton(
                      onPressed: () {
                        setModalState(() {
                          selectedScore = score;
                        });
                      },
                      iconSize: 28,
                      padding: const EdgeInsets.all(4),
                      constraints: const BoxConstraints(),
                      icon: Icon(
                        active ? Icons.star_rounded : Icons.star_border_rounded,
                        color: active
                            ? const Color(0xFFF59E0B)
                            : BrandConfig.textMutedOf(context),
                      ),
                    );
                  }),
                ),
                const SizedBox(height: 16),
                TextFormField(
                  initialValue: commentDraft,
                  minLines: 2,
                  maxLines: 4,
                  decoration: const InputDecoration(
                    labelText: 'Yorum',
                    hintText: 'İsteğe bağlı kısa yorum',
                  ),
                  onChanged: (value) {
                    commentDraft = value;
                  },
                ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(context).pop(),
              child: const Text('Vazgeç'),
            ),
            FilledButton(
              onPressed: () => Navigator.of(context).pop(
                {
                  'score': selectedScore,
                  'comment': commentDraft.trim(),
                },
              ),
              child: Text(_rating == null ? 'Puanı kaydet' : 'Güncelle'),
            ),
          ],
        ),
      ),
    );
    return result;
  }

  Future<bool> _confirm({
    required String title,
    required String message,
  }) async {
    final result = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: BrandConfig.surfaceOf(context),
        title: Text(title),
        content: Text(message),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Vazgeç'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Onayla'),
          ),
        ],
      ),
    );
    return result == true;
  }

  Future<void> _openThread() async {
    await Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (_) => RequestThreadScreen(
          sessionController: widget.sessionController,
          dataService: widget.dataService,
          requestId: widget.requestId,
          title: (_request['service_type'] ?? 'Talep').toString(),
          subtitle:
              '${(_request['city'] ?? '').toString()} / ${(_request['district'] ?? '').toString()}',
        ),
      ),
    );
    await _load();
  }

  Future<void> _openProviderProfile(int providerId) async {
    await Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (_) => ProviderDetailScreen(
          sessionController: widget.sessionController,
          dataService: widget.dataService,
          providerId: providerId,
        ),
      ),
    );
  }

  String _toLocalIsoString(DateTime value) {
    String two(int number) => number.toString().padLeft(2, '0');
    return '${value.year}-${two(value.month)}-${two(value.day)}T${two(value.hour)}:${two(value.minute)}';
  }

  String _formatDateTime(String rawValue) {
    final parsed = DateTime.tryParse(rawValue);
    if (parsed == null) {
      return rawValue;
    }
    final local = parsed.toLocal();
    String two(int value) => value.toString().padLeft(2, '0');
    return '${two(local.day)}.${two(local.month)}.${local.year} ${two(local.hour)}:${two(local.minute)}';
  }

  String _requestStatusLabel(String status) {
    switch (status) {
      case 'new':
        return 'Yeni';
      case 'pending_provider':
        return 'Usta yanıtı bekleniyor';
      case 'pending_customer':
        return 'Karar bekleniyor';
      case 'matched':
        return 'Eşleşti';
      case 'completed':
        return 'Tamamlandı';
      case 'cancelled':
        return 'İptal edildi';
      default:
        return status.isEmpty ? 'Durum yok' : status;
    }
  }

  String _appointmentStatusLabel(String status) {
    switch (status) {
      case 'pending':
        return 'Usta onayı bekleniyor';
      case 'pending_customer':
        return 'Sizin onayınız bekleniyor';
      case 'confirmed':
        return 'Onaylandı';
      case 'rejected':
        return 'Reddedildi';
      case 'cancelled':
        return 'İptal edildi';
      case 'completed':
        return 'Tamamlandı';
      default:
        return status.isEmpty ? '' : status;
    }
  }

  String _providerOfferStatusLabel(String status) {
    switch (status) {
      case 'pending':
        return 'Bekliyor';
      case 'accepted':
        return 'Kabul edildi';
      case 'rejected':
        return 'Reddedildi';
      case 'expired':
        return 'Süresi doldu';
      case 'failed':
        return 'Gönderilemedi';
      default:
        return status.isEmpty ? 'Durum yok' : status;
    }
  }

  String _requestStageSummary() {
    final requestStatus = (_request['status'] ?? '').toString();
    final appointmentStatus = (_appointment?['status'] ?? '').toString();

    switch (requestStatus) {
      case 'new':
        return 'Talep oluşturuldu. Şu anda uygun ustalara yönlendirilmesi bekleniyor.';
      case 'pending_provider':
        return 'Talebiniz ustalara iletildi. Şu anda usta yanıtları bekleniyor.';
      case 'pending_customer':
        return 'Teklifler hazır. Bir usta seçerek süreci devam ettirebilirsiniz.';
      case 'matched':
        switch (appointmentStatus) {
          case 'pending':
            return 'Bir usta ile eşleştiniz. Randevu için usta onayı bekleniyor.';
          case 'pending_customer':
            return 'Bir usta ile eşleştiniz. Randevuyu sizin onaylamanız bekleniyor.';
          case 'confirmed':
            return 'İş aktif durumda. Randevu onaylandı ve süreç devam ediyor.';
          case 'completed':
            return 'İş tamamlandı. Bu kayıt geçmişe taşınacaktır.';
          case 'rejected':
          case 'cancelled':
            return 'Randevu kapandı. Gerekirse yeni bir randevu planlayabilirsiniz.';
          default:
            return 'Bir usta ile eşleştiniz. İş şu anda aktif olarak devam ediyor.';
        }
      case 'completed':
        return 'İş tamamlandı. Bu kayıt artık geçmişte gösterilir.';
      case 'cancelled':
        return 'Talep iptal edildi. Bu kayıt artık geçmişte gösterilir.';
      default:
        return 'Süreç bilgisi güncelleniyor.';
    }
  }

  int _currentFlowStep() {
    final rawStep = (_flowState['step'] ?? '').toString();
    final match = RegExp(r'(\d+)\s*/\s*(\d+)').firstMatch(rawStep);
    if (match != null) {
      final parsed = int.tryParse(match.group(1) ?? '');
      if (parsed != null) {
        return parsed.clamp(0, _flowLabels.length).toInt();
      }
    }

    final status = (_request['status'] ?? '').toString();
    if (status == 'completed') {
      return _flowLabels.length;
    }
    if (status == 'cancelled') {
      return 0;
    }
    if (status == 'matched') {
      return (_payload['calendar_enabled'] == true && _flowLabels.length >= 4)
          ? 3
          : _flowLabels.length;
    }
    if (status == 'pending_customer') {
      return _flowLabels.length >= 2 ? 2 : 1;
    }
    return 1;
  }

  Color _flowToneColor(BuildContext context) {
    switch ((_flowState['tone'] ?? '').toString()) {
      case 'success':
        return const Color(0xFF15803D);
      case 'danger':
        return const Color(0xFFB91C1C);
      case 'waiting':
        return const Color(0xFFD97706);
      case 'action':
        return BrandConfig.accentOf(context);
      default:
        return BrandConfig.textMutedOf(context);
    }
  }

  Future<void> _pickAppointmentDateTime() async {
    final date = await showDatePicker(
      context: context,
      firstDate: DateTime.now(),
      lastDate: DateTime.now().add(const Duration(days: 90)),
      initialDate: DateTime.now().add(const Duration(days: 1)),
    );
    if (date == null || !mounted) {
      return;
    }
    final time = await showTimePicker(
      context: context,
      initialTime: TimeOfDay.now(),
    );
    if (time == null || !mounted) {
      return;
    }
    var noteDraft = '';
    final note = await showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: BrandConfig.surfaceOf(context),
        title: const Text('Randevu notu'),
        content: TextFormField(
          maxLength:
              ((_payload['short_note_max_length'] as num?)?.toInt() ?? 100),
          minLines: 1,
          maxLines: 3,
          onChanged: (value) {
            noteDraft = value;
          },
          decoration: const InputDecoration(
            hintText: 'İsteğe bağlı kısa not',
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Vazgeç'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(noteDraft.trim()),
            child: const Text('Gönder'),
          ),
        ],
      ),
    );
    if (note == null || !mounted) {
      return;
    }

    final scheduled = DateTime(
      date.year,
      date.month,
      date.day,
      time.hour,
      time.minute,
    );
    final isoString = _toLocalIsoString(scheduled);
    final accessToken = await widget.sessionController.ensureAccessToken();
    await _performAndPop(
      () => widget.dataService.createAppointment(
        accessToken: accessToken,
        requestId: widget.requestId,
        scheduledFor: isoString,
        customerNote: note,
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return const Scaffold(
        body: BrandBackdrop(
          child: Center(child: CircularProgressIndicator()),
        ),
      );
    }

    if (_error != null && _payload.isEmpty) {
      return Scaffold(
        appBar: AppBar(title: const Text('Talep detayı')),
        body: BrandBackdrop(
          child: Center(
            child: Padding(
              padding: const EdgeInsets.all(24),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(
                    _error!,
                    textAlign: TextAlign.center,
                    style: TextStyle(color: BrandConfig.textMutedOf(context)),
                  ),
                  const SizedBox(height: 16),
                  FilledButton.icon(
                    onPressed: _load,
                    icon: const Icon(Icons.refresh_rounded),
                    label: const Text('Tekrar dene'),
                  ),
                ],
              ),
            ),
          ),
        ),
      );
    }

    final matchedProviderId = (_matchedProvider?['id'] as num?)?.toInt();
    final providerOfferId = (_providerOffer?['id'] as num?)?.toInt();
    final appointmentId = (_appointment?['id'] as num?)?.toInt();

    return Scaffold(
      appBar: AppBar(title: const Text('Talep detayı')),
      body: BrandBackdrop(
        child: ListView(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 24),
          children: [
            if (_liveUpdateMessage != null) ...[
              Container(
                width: double.infinity,
                margin: const EdgeInsets.only(bottom: 12),
                padding: const EdgeInsets.symmetric(
                  horizontal: 14,
                  vertical: 12,
                ),
                decoration: BoxDecoration(
                  color: BrandConfig.accentSoftOf(context),
                  borderRadius: BorderRadius.circular(18),
                  border: Border.all(color: BrandConfig.borderOf(context)),
                ),
                child: Row(
                  children: [
                    Icon(
                      Icons.sync_rounded,
                      size: 18,
                      color: BrandConfig.accentOf(context),
                    ),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Text(
                        _liveUpdateMessage!,
                        style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                              color: BrandConfig.textOf(context),
                              fontWeight: FontWeight.w700,
                            ),
                      ),
                    ),
                  ],
                ),
              ),
            ],
            Container(
              padding: const EdgeInsets.all(20),
              decoration: BrandConfig.heroPanelDecorationOf(context),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    (_request['service_type'] ?? 'Talep').toString(),
                    style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                          color: BrandConfig.textOf(context),
                          fontWeight: FontWeight.w800,
                        ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    '${(_request['request_code'] ?? '').toString()} · ${(_request['city'] ?? '').toString()} / ${(_request['district'] ?? '').toString()}',
                    style:
                        TextStyle(color: BrandConfig.heroTextMutedOf(context)),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    (_request['details'] ?? '').toString(),
                    style: TextStyle(
                      color: BrandConfig.heroTextMutedOf(context),
                      height: 1.4,
                    ),
                  ),
                ],
              ),
            ),
            if (_error != null)
              Padding(
                padding: const EdgeInsets.only(top: 12),
                child: Text(
                  _error!,
                  style: TextStyle(color: BrandConfig.errorTextOf(context)),
                ),
              ),
            if (_flowState.isNotEmpty) ...[
              const SizedBox(height: 12),
              _FlowTimelineCard(
                stepLabel: (_flowState['step'] ?? '').toString(),
                title: (_flowState['title'] ?? '').toString(),
                hint: (_flowState['hint'] ?? '').toString(),
                nextAction: (_flowState['next_action'] ?? '').toString(),
                labels: _flowLabels,
                currentStep: _currentFlowStep(),
                toneColor: _flowToneColor(context),
              ),
            ],
            const SizedBox(height: 12),
            Card(
              child: Padding(
                padding: const EdgeInsets.all(18),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Durum',
                      style: Theme.of(context).textTheme.titleMedium?.copyWith(
                            fontWeight: FontWeight.w700,
                          ),
                    ),
                    const SizedBox(height: 10),
                    Wrap(
                      spacing: 10,
                      runSpacing: 10,
                      children: [
                        _InfoChip(
                          label: 'Statü',
                          value: _requestStatusLabel(
                            (_request['status'] ?? '').toString(),
                          ),
                        ),
                        if ((_appointment?['status'] ?? '')
                            .toString()
                            .isNotEmpty)
                          _InfoChip(
                            label: 'Randevu',
                            value: _appointmentStatusLabel(
                              (_appointment?['status'] ?? '').toString(),
                            ),
                          ),
                        _InfoChip(
                          label: 'Okunmamış',
                          value: '${(_request['unread_messages'] ?? 0)}',
                        ),
                        if ((_request['created_at'] ?? '')
                            .toString()
                            .isNotEmpty)
                          _InfoChip(
                            label: 'Oluşturuldu',
                            value: _formatDateTime(
                              (_request['created_at'] ?? '').toString(),
                            ),
                          ),
                      ],
                    ),
                    if (_flowState.isEmpty) ...[
                      const SizedBox(height: 12),
                      Text(
                        _requestStageSummary(),
                        style: TextStyle(
                          color: BrandConfig.textMutedOf(context),
                          height: 1.45,
                        ),
                      ),
                    ],
                    if ((_actions['complete_block_reason'] ?? '')
                        .toString()
                        .isNotEmpty) ...[
                      const SizedBox(height: 12),
                      Text(
                        (_actions['complete_block_reason'] ?? '').toString(),
                        style:
                            TextStyle(color: BrandConfig.textMutedOf(context)),
                      ),
                    ],
                  ],
                ),
              ),
            ),
            if (_matchedProvider != null) ...[
              const SizedBox(height: 12),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(18),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Eşleşen usta',
                        style:
                            Theme.of(context).textTheme.titleMedium?.copyWith(
                                  fontWeight: FontWeight.w700,
                                ),
                      ),
                      const SizedBox(height: 10),
                      Text(
                        (_matchedProvider?['full_name'] ?? '').toString(),
                        style: TextStyle(
                          color: BrandConfig.textOf(context),
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      const SizedBox(height: 6),
                      Text(
                        '${(_matchedProvider?['city'] ?? '').toString()} / ${(_matchedProvider?['district'] ?? '').toString()}',
                        style:
                            TextStyle(color: BrandConfig.textMutedOf(context)),
                      ),
                      if (matchedProviderId != null) ...[
                        const SizedBox(height: 12),
                        FilledButton.tonalIcon(
                          onPressed: () =>
                              _openProviderProfile(matchedProviderId),
                          icon: const Icon(Icons.person_search_rounded),
                          label: const Text('Profilini aç'),
                        ),
                      ],
                    ],
                  ),
                ),
              ),
            ],
            if (_appointment != null) ...[
              const SizedBox(height: 12),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(18),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Randevu',
                        style:
                            Theme.of(context).textTheme.titleMedium?.copyWith(
                                  fontWeight: FontWeight.w700,
                                ),
                      ),
                      const SizedBox(height: 10),
                      _DetailLine(
                        label: 'Durum',
                        value: _appointmentStatusLabel(
                          (_appointment?['status'] ?? '').toString(),
                        ),
                      ),
                      if ((_appointment?['scheduled_for'] ?? '')
                          .toString()
                          .isNotEmpty)
                        _DetailLine(
                          label: 'Tarih',
                          value: _formatDateTime(
                            (_appointment?['scheduled_for'] ?? '').toString(),
                          ),
                        ),
                      if ((_appointment?['customer_note'] ?? '')
                          .toString()
                          .isNotEmpty)
                        _DetailLine(
                          label: 'Müşteri notu',
                          value:
                              (_appointment?['customer_note'] ?? '').toString(),
                        ),
                      if ((_appointment?['provider_note'] ?? '')
                          .toString()
                          .isNotEmpty)
                        _DetailLine(
                          label: 'Usta notu',
                          value:
                              (_appointment?['provider_note'] ?? '').toString(),
                        ),
                    ],
                  ),
                ),
              ),
            ],
            if (_providerOffer != null) ...[
              const SizedBox(height: 12),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(18),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Teklif durumu',
                        style:
                            Theme.of(context).textTheme.titleMedium?.copyWith(
                                  fontWeight: FontWeight.w700,
                                ),
                      ),
                      const SizedBox(height: 10),
                      _DetailLine(
                        label: 'Durum',
                        value: _providerOfferStatusLabel(
                          (_providerOffer?['status'] ?? '').toString(),
                        ),
                      ),
                      if ((_providerOffer?['quote_note'] ?? '')
                          .toString()
                          .isNotEmpty)
                        _DetailLine(
                          label: 'Not',
                          value:
                              (_providerOffer?['quote_note'] ?? '').toString(),
                        ),
                    ],
                  ),
                ),
              ),
            ],
            if (_acceptedOffers.isNotEmpty) ...[
              const SizedBox(height: 12),
              Text(
                'Hazır teklifler',
                style: Theme.of(context).textTheme.titleLarge?.copyWith(
                      fontWeight: FontWeight.w800,
                    ),
              ),
              const SizedBox(height: 10),
              for (final offer in _acceptedOffers)
                _AcceptedOfferCard(
                  offer: offer,
                  canSelect:
                      _actions['can_select_offer'] == true && !_actionLoading,
                  onOpenProfile: () async {
                    final providerId =
                        (((offer['provider'] as Map?)?['id']) as num?)?.toInt();
                    if (providerId != null) {
                      await _openProviderProfile(providerId);
                    }
                  },
                  onSelect: () async {
                    final accessToken =
                        await widget.sessionController.ensureAccessToken();
                    final offerId = (offer['id'] as num?)?.toInt();
                    if (offerId == null) {
                      return;
                    }
                    await _performAndPop(
                      () => widget.dataService.selectOffer(
                        accessToken: accessToken,
                        requestId: widget.requestId,
                        offerId: offerId,
                      ),
                    );
                  },
                ),
            ],
            if (!_isProviderViewer &&
                (_rating != null ||
                    _ratingState['can_rate'] == true ||
                    ((_ratingState['rate_block_reason'] ?? '')
                        .toString()
                        .isNotEmpty))) ...[
              const SizedBox(height: 12),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(18),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Puanlama',
                        style:
                            Theme.of(context).textTheme.titleMedium?.copyWith(
                                  fontWeight: FontWeight.w700,
                                ),
                      ),
                      const SizedBox(height: 10),
                      if (_rating != null) ...[
                        _DetailLine(
                          label: 'Puanın',
                          value: '${(_rating?['score'] ?? 0)}/5',
                        ),
                        if (((_rating?['comment'] ?? '').toString())
                            .trim()
                            .isNotEmpty)
                          _DetailLine(
                            label: 'Yorumun',
                            value: (_rating?['comment'] ?? '').toString(),
                          ),
                        if (((_rating?['updated_at'] ?? '').toString())
                            .trim()
                            .isNotEmpty)
                          _DetailLine(
                            label: 'Güncellendi',
                            value: _formatDateTime(
                              (_rating?['updated_at'] ?? '').toString(),
                            ),
                          ),
                      ] else
                        Text(
                          'İş tamamlandığında usta için puan ve yorum bırakabilirsiniz.',
                          style: TextStyle(
                            color: BrandConfig.textMutedOf(context),
                            height: 1.4,
                          ),
                        ),
                      if ((_ratingState['rate_block_reason'] ?? '')
                          .toString()
                          .isNotEmpty) ...[
                        const SizedBox(height: 10),
                        Text(
                          (_ratingState['rate_block_reason'] ?? '').toString(),
                          style: TextStyle(
                            color: BrandConfig.textMutedOf(context),
                            height: 1.4,
                          ),
                        ),
                      ],
                      if (_ratingState['can_rate'] == true) ...[
                        const SizedBox(height: 12),
                        if (_isRatingEditorOpen) ...[
                          Text(
                            _rating == null
                                ? 'Ustayı puanla'
                                : 'Puanını güncelle',
                            style: Theme.of(context)
                                .textTheme
                                .titleSmall
                                ?.copyWith(
                                  fontWeight: FontWeight.w800,
                                ),
                          ),
                          const SizedBox(height: 10),
                          Wrap(
                            spacing: 4,
                            children: List<Widget>.generate(5, (index) {
                              final score = index + 1;
                              final active = score <= _ratingDraftScore;
                              return IconButton(
                                onPressed: _actionLoading
                                    ? null
                                    : () {
                                        setState(() {
                                          _ratingDraftScore = score;
                                        });
                                      },
                                iconSize: 28,
                                padding: const EdgeInsets.all(4),
                                constraints: const BoxConstraints(),
                                icon: Icon(
                                  active
                                      ? Icons.star_rounded
                                      : Icons.star_border_rounded,
                                  color: active
                                      ? const Color(0xFFF59E0B)
                                      : BrandConfig.textMutedOf(context),
                                ),
                              );
                            }),
                          ),
                          const SizedBox(height: 12),
                          TextField(
                            controller: _ratingCommentController,
                            minLines: 2,
                            maxLines: 4,
                            enabled: !_actionLoading,
                            decoration: const InputDecoration(
                              labelText: 'Yorum',
                              hintText: 'İsteğe bağlı kısa yorum',
                            ),
                          ),
                          const SizedBox(height: 12),
                          Row(
                            children: [
                              Expanded(
                                child: OutlinedButton(
                                  onPressed: _actionLoading
                                      ? null
                                      : _closeRatingEditor,
                                  child: const Text('Vazgeç'),
                                ),
                              ),
                              const SizedBox(width: 10),
                              Expanded(
                                child: FilledButton.icon(
                                  onPressed: _actionLoading
                                      ? null
                                      : () => _submitRating(
                                            {
                                              'score': _ratingDraftScore,
                                              'comment':
                                                  _ratingCommentController.text
                                                      .trim(),
                                            },
                                          ),
                                  icon: const Icon(Icons.star_rounded),
                                  label: Text(
                                    _rating == null
                                        ? 'Puanı kaydet'
                                        : 'Güncelle',
                                  ),
                                ),
                              ),
                            ],
                          ),
                        ] else
                          FilledButton.tonalIcon(
                            onPressed:
                                _actionLoading ? null : _openRatingEditor,
                            icon: const Icon(Icons.star_rounded),
                            label: Text(
                              _rating == null ? 'Puan ver' : 'Puanı güncelle',
                            ),
                          ),
                      ],
                    ],
                  ),
                ),
              ),
            ],
            const SizedBox(height: 12),
            Text(
              'Aksiyonlar',
              style: Theme.of(context).textTheme.titleLarge?.copyWith(
                    fontWeight: FontWeight.w800,
                  ),
            ),
            const SizedBox(height: 10),
            _ActionWrap(
              actions: [
                if (_actions['can_open_messages'] == true)
                  _ActionSpec(
                    label: 'Mesajlar',
                    icon: Icons.forum_outlined,
                    onTap: _openThread,
                    primary: false,
                  ),
                if (!_isProviderViewer &&
                    _actions['can_cancel_request'] == true)
                  _ActionSpec(
                    label: 'Talebi iptal et',
                    icon: Icons.cancel_outlined,
                    onTap: () async {
                      final confirmed = await _confirm(
                        title: 'Talebi iptal et',
                        message:
                            'Bu talep için mevcut akışı sonlandırmak istiyor musunuz?',
                      );
                      if (!confirmed || !mounted) {
                        return;
                      }
                      final accessToken =
                          await widget.sessionController.ensureAccessToken();
                      await _performAndPop(
                        () => widget.dataService.cancelRequest(
                          accessToken: accessToken,
                          requestId: widget.requestId,
                        ),
                      );
                    },
                    primary: false,
                  ),
                if (!_isProviderViewer &&
                    _actions['can_create_appointment'] == true)
                  _ActionSpec(
                    label: 'Randevu planla',
                    icon: Icons.event_available_rounded,
                    onTap: _pickAppointmentDateTime,
                    primary: false,
                  ),
                if (!_isProviderViewer &&
                    _actions['can_cancel_appointment'] == true)
                  _ActionSpec(
                    label: 'Randevuyu iptal et',
                    icon: Icons.event_busy_rounded,
                    onTap: () async {
                      final confirmed = await _confirm(
                        title: 'Randevuyu iptal et',
                        message: 'Bu randevuyu iptal etmek istiyor musunuz?',
                      );
                      if (!confirmed || !mounted) {
                        return;
                      }
                      final accessToken =
                          await widget.sessionController.ensureAccessToken();
                      await _performAndPop(
                        () => widget.dataService.cancelAppointment(
                          accessToken: accessToken,
                          requestId: widget.requestId,
                        ),
                      );
                    },
                    primary: false,
                  ),
                if (!_isProviderViewer &&
                    _actions['can_complete_request'] == true)
                  _ActionSpec(
                    label: 'İşi bitir',
                    icon: Icons.task_alt_rounded,
                    onTap: () async {
                      final confirmed = await _confirm(
                        title: 'İşi tamamla',
                        message:
                            'Bu işi tamamlandı olarak işaretlemek istiyor musunuz?',
                      );
                      if (!confirmed || !mounted) {
                        return;
                      }
                      final accessToken =
                          await widget.sessionController.ensureAccessToken();
                      await _performAndPop(
                        () => widget.dataService.completeRequest(
                          accessToken: accessToken,
                          requestId: widget.requestId,
                        ),
                      );
                    },
                    primary: true,
                  ),
                if (_isProviderViewer &&
                    _actions['can_accept_offer'] == true &&
                    providerOfferId != null)
                  _ActionSpec(
                    label: 'Teklifi onayla',
                    icon: Icons.check_circle_outline_rounded,
                    onTap: () async {
                      final note = await _promptForShortNote(
                        title: 'Teklifi onayla',
                        hintText: 'Kısa not (opsiyonel)',
                      );
                      if (note == null || !mounted) {
                        return;
                      }
                      final accessToken =
                          await widget.sessionController.ensureAccessToken();
                      await _performAndPop(
                        () => widget.dataService.acceptProviderOffer(
                          accessToken: accessToken,
                          offerId: providerOfferId,
                          quoteNote: note,
                        ),
                      );
                    },
                    primary: true,
                  ),
                if (_isProviderViewer &&
                    _actions['can_reject_offer'] == true &&
                    providerOfferId != null)
                  _ActionSpec(
                    label: 'Teklifi reddet',
                    icon: Icons.close_rounded,
                    onTap: () async {
                      final confirmed = await _confirm(
                        title: 'Teklifi reddet',
                        message: 'Bu teklifi reddetmek istiyor musunuz?',
                      );
                      if (!confirmed || !mounted) {
                        return;
                      }
                      final accessToken =
                          await widget.sessionController.ensureAccessToken();
                      await _performAndPop(
                        () => widget.dataService.rejectProviderOffer(
                          accessToken: accessToken,
                          offerId: providerOfferId,
                        ),
                      );
                    },
                    primary: false,
                  ),
                if (_isProviderViewer &&
                    _actions['can_withdraw_offer'] == true &&
                    providerOfferId != null)
                  _ActionSpec(
                    label: 'Teklifi geri çek',
                    icon: Icons.undo_rounded,
                    onTap: () async {
                      final confirmed = await _confirm(
                        title: 'Teklifi geri çek',
                        message: 'Bu teklifi geri çekmek istiyor musunuz?',
                      );
                      if (!confirmed || !mounted) {
                        return;
                      }
                      final accessToken =
                          await widget.sessionController.ensureAccessToken();
                      await _performAndPop(
                        () => widget.dataService.withdrawProviderOffer(
                          accessToken: accessToken,
                          offerId: providerOfferId,
                        ),
                      );
                    },
                    primary: false,
                  ),
                if (_isProviderViewer &&
                    _actions['can_confirm_appointment'] == true &&
                    appointmentId != null)
                  _ActionSpec(
                    label: 'Randevuyu onayla',
                    icon: Icons.event_available_rounded,
                    onTap: () async {
                      final note = await _promptForShortNote(
                        title: 'Randevuyu onayla',
                        hintText: 'Kısa not (opsiyonel)',
                      );
                      if (note == null || !mounted) {
                        return;
                      }
                      final accessToken =
                          await widget.sessionController.ensureAccessToken();
                      await _performAndPop(
                        () => widget.dataService.confirmProviderAppointment(
                          accessToken: accessToken,
                          appointmentId: appointmentId,
                          providerNote: note,
                        ),
                      );
                    },
                    primary: true,
                  ),
                if (_isProviderViewer &&
                    _actions['can_reject_appointment'] == true &&
                    appointmentId != null)
                  _ActionSpec(
                    label: 'Randevuyu reddet',
                    icon: Icons.event_busy_rounded,
                    onTap: () async {
                      final note = await _promptForShortNote(
                        title: 'Randevuyu reddet',
                        hintText: 'Kısa not (opsiyonel)',
                      );
                      if (note == null || !mounted) {
                        return;
                      }
                      final accessToken =
                          await widget.sessionController.ensureAccessToken();
                      await _performAndPop(
                        () => widget.dataService.rejectProviderAppointment(
                          accessToken: accessToken,
                          appointmentId: appointmentId,
                          providerNote: note,
                        ),
                      );
                    },
                    primary: false,
                  ),
                if (_isProviderViewer &&
                    _actions['can_complete_appointment'] == true &&
                    appointmentId != null)
                  _ActionSpec(
                    label: 'İşi bitir',
                    icon: Icons.task_alt_rounded,
                    onTap: () async {
                      final confirmed = await _confirm(
                        title: 'İşi tamamla',
                        message:
                            'Bu işi tamamlandı olarak işaretlemek istiyor musunuz?',
                      );
                      if (!confirmed || !mounted) {
                        return;
                      }
                      final accessToken =
                          await widget.sessionController.ensureAccessToken();
                      await _performAndPop(
                        () => widget.dataService.completeProviderAppointment(
                          accessToken: accessToken,
                          appointmentId: appointmentId,
                        ),
                      );
                    },
                    primary: true,
                  ),
                if (_isProviderViewer &&
                    _actions['can_release_request'] == true)
                  _ActionSpec(
                    label: 'Eşleşmeyi sonlandır',
                    icon: Icons.link_off_rounded,
                    onTap: () async {
                      final confirmed = await _confirm(
                        title: 'Eşleşmeyi sonlandır',
                        message:
                            'Bu işi sonlandırıp tekrar yönlendirmek istiyor musunuz?',
                      );
                      if (!confirmed || !mounted) {
                        return;
                      }
                      final accessToken =
                          await widget.sessionController.ensureAccessToken();
                      await _performAndPop(
                        () => widget.dataService.releaseProviderRequest(
                          accessToken: accessToken,
                          requestId: widget.requestId,
                        ),
                      );
                    },
                    primary: false,
                  ),
              ],
              disabled: _actionLoading,
            ),
            if (_actionLoading)
              const Padding(
                padding: EdgeInsets.only(top: 16),
                child: Center(child: CircularProgressIndicator()),
              ),
          ],
        ),
      ),
    );
  }
}

class _InfoChip extends StatelessWidget {
  const _InfoChip({
    required this.label,
    required this.value,
  });

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        color: BrandConfig.surfaceAltOf(context),
        borderRadius: BorderRadius.circular(16),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            label,
            style: TextStyle(
              color: BrandConfig.textMutedOf(context),
              fontSize: 12,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            value,
            style: TextStyle(
              color: BrandConfig.textOf(context),
              fontWeight: FontWeight.w700,
            ),
          ),
        ],
      ),
    );
  }
}

class _FlowTimelineCard extends StatelessWidget {
  const _FlowTimelineCard({
    required this.stepLabel,
    required this.title,
    required this.hint,
    required this.nextAction,
    required this.labels,
    required this.currentStep,
    required this.toneColor,
  });

  final String stepLabel;
  final String title;
  final String hint;
  final String nextAction;
  final List<String> labels;
  final int currentStep;
  final Color toneColor;

  @override
  Widget build(BuildContext context) {
    final safeStep = currentStep.clamp(0, labels.length).toInt();
    final currentIndex =
        safeStep > 0 && safeStep <= labels.length ? safeStep - 1 : null;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(18),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Text(
                  'Süreç akışı',
                  style: Theme.of(context).textTheme.titleMedium?.copyWith(
                        fontWeight: FontWeight.w800,
                      ),
                ),
                const Spacer(),
                if (stepLabel.trim().isNotEmpty)
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 10,
                      vertical: 6,
                    ),
                    decoration: BoxDecoration(
                      color: toneColor.withValues(alpha: 0.12),
                      borderRadius: BorderRadius.circular(999),
                      border: Border.all(
                        color: toneColor.withValues(alpha: 0.22),
                      ),
                    ),
                    child: Text(
                      stepLabel,
                      style: TextStyle(
                        color: toneColor,
                        fontSize: 12,
                        fontWeight: FontWeight.w800,
                      ),
                    ),
                  ),
              ],
            ),
            if (title.trim().isNotEmpty) ...[
              const SizedBox(height: 12),
              Text(
                title,
                style: Theme.of(context).textTheme.titleLarge?.copyWith(
                      fontWeight: FontWeight.w800,
                    ),
              ),
            ],
            if (hint.trim().isNotEmpty) ...[
              const SizedBox(height: 8),
              Text(
                hint,
                style: TextStyle(
                  color: BrandConfig.textMutedOf(context),
                  height: 1.45,
                ),
              ),
            ],
            if (labels.isNotEmpty) ...[
              const SizedBox(height: 18),
              for (var index = 0; index < labels.length; index++)
                _FlowTimelineStep(
                  label: labels[index],
                  isCurrent: currentIndex == index,
                  isComplete: currentIndex != null && index < currentIndex,
                  isLast: index == labels.length - 1,
                  accentColor: toneColor,
                ),
            ],
            if (nextAction.trim().isNotEmpty) ...[
              const SizedBox(height: 18),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  color: toneColor.withValues(alpha: 0.08),
                  borderRadius: BorderRadius.circular(20),
                  border: Border.all(
                    color: toneColor.withValues(alpha: 0.18),
                  ),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Sıradaki adım',
                      style: TextStyle(
                        color: toneColor,
                        fontSize: 12,
                        fontWeight: FontWeight.w800,
                      ),
                    ),
                    const SizedBox(height: 6),
                    Text(
                      nextAction,
                      style: TextStyle(
                        color: BrandConfig.textOf(context),
                        height: 1.4,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

class _FlowTimelineStep extends StatelessWidget {
  const _FlowTimelineStep({
    required this.label,
    required this.isCurrent,
    required this.isComplete,
    required this.isLast,
    required this.accentColor,
  });

  final String label;
  final bool isCurrent;
  final bool isComplete;
  final bool isLast;
  final Color accentColor;

  @override
  Widget build(BuildContext context) {
    final baseColor = BrandConfig.textMutedOf(context);
    final lineColor = isCurrent || isComplete
        ? accentColor.withValues(alpha: isCurrent ? 0.65 : 0.3)
        : BrandConfig.borderOf(context);
    final markerColor = isCurrent
        ? accentColor
        : isComplete
            ? accentColor.withValues(alpha: 0.2)
            : Colors.transparent;
    final markerBorderColor = isCurrent || isComplete ? accentColor : lineColor;
    final textColor = isCurrent
        ? BrandConfig.textOf(context)
        : BrandConfig.textMutedOf(context);

    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(
          width: 24,
          child: Column(
            children: [
              Container(
                width: 14,
                height: 14,
                decoration: BoxDecoration(
                  color: markerColor,
                  shape: BoxShape.circle,
                  border: Border.all(color: markerBorderColor, width: 2),
                ),
                child: isComplete
                    ? Icon(
                        Icons.check_rounded,
                        size: 9,
                        color: accentColor,
                      )
                    : isCurrent
                        ? Icon(
                            Icons.circle,
                            size: 6,
                            color: Colors.white,
                          )
                        : null,
              ),
              if (!isLast)
                Container(
                  width: 2,
                  height: 26,
                  margin: const EdgeInsets.symmetric(vertical: 4),
                  color: lineColor,
                ),
            ],
          ),
        ),
        const SizedBox(width: 10),
        Expanded(
          child: Padding(
            padding: const EdgeInsets.only(top: 1),
            child: Row(
              children: [
                Expanded(
                  child: Text(
                    label,
                    style: TextStyle(
                      color: textColor,
                      fontWeight: isCurrent ? FontWeight.w800 : FontWeight.w600,
                    ),
                  ),
                ),
                if (isCurrent)
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 8,
                      vertical: 4,
                    ),
                    decoration: BoxDecoration(
                      color: accentColor.withValues(alpha: 0.12),
                      borderRadius: BorderRadius.circular(999),
                    ),
                    child: Text(
                      'Şimdi',
                      style: TextStyle(
                        color: accentColor,
                        fontSize: 11,
                        fontWeight: FontWeight.w800,
                      ),
                    ),
                  ),
                if (!isCurrent && isComplete)
                  Text(
                    'Tamam',
                    style: TextStyle(
                      color: accentColor,
                      fontSize: 11,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                if (!isCurrent && !isComplete)
                  Text(
                    'Sırada',
                    style: TextStyle(
                      color: baseColor,
                      fontSize: 11,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
              ],
            ),
          ),
        ),
      ],
    );
  }
}

class _AcceptedOfferCard extends StatelessWidget {
  const _AcceptedOfferCard({
    required this.offer,
    required this.canSelect,
    required this.onOpenProfile,
    required this.onSelect,
  });

  final Map<String, dynamic> offer;
  final bool canSelect;
  final Future<void> Function() onOpenProfile;
  final Future<void> Function() onSelect;

  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      child: Padding(
        padding: const EdgeInsets.all(18),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                  child: Text(
                    ((offer['provider'] as Map?)?['full_name'] ?? 'Usta')
                        .toString(),
                    style: TextStyle(
                      color: BrandConfig.textOf(context),
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                ),
                if (offer['is_recommended'] == true)
                  Container(
                    padding:
                        const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                    decoration: BoxDecoration(
                      color: BrandConfig.accentSoftOf(context),
                      borderRadius: BorderRadius.circular(999),
                    ),
                    child: const Text('Önerilen'),
                  ),
              ],
            ),
            const SizedBox(height: 8),
            if (((offer['quote_note'] ?? '').toString()).isNotEmpty)
              Text(
                (offer['quote_note'] ?? '').toString(),
                style: TextStyle(color: BrandConfig.textMutedOf(context)),
              ),
            const SizedBox(height: 12),
            Row(
              children: [
                Expanded(
                  child: FilledButton.tonal(
                    onPressed: onOpenProfile,
                    child: const Text('Profil'),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: FilledButton(
                    onPressed: canSelect ? onSelect : null,
                    child: const Text('Ustayı seç'),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

class _ActionSpec {
  const _ActionSpec({
    required this.label,
    required this.icon,
    required this.onTap,
    required this.primary,
  });

  final String label;
  final IconData icon;
  final Future<void> Function() onTap;
  final bool primary;
}

class _ActionWrap extends StatelessWidget {
  const _ActionWrap({
    required this.actions,
    required this.disabled,
  });

  final List<_ActionSpec> actions;
  final bool disabled;

  @override
  Widget build(BuildContext context) {
    if (actions.isEmpty) {
      return Text(
        'Bu kayıt için şu anda uygulanabilir bir aksiyon yok.',
        style: TextStyle(color: BrandConfig.textMutedOf(context)),
      );
    }

    return Wrap(
      spacing: 10,
      runSpacing: 10,
      children: actions
          .map(
            (item) => item.primary
                ? FilledButton.icon(
                    onPressed: disabled ? null : item.onTap,
                    icon: Icon(item.icon),
                    label: Text(item.label),
                  )
                : FilledButton.tonalIcon(
                    onPressed: disabled ? null : item.onTap,
                    icon: Icon(item.icon),
                    label: Text(item.label),
                  ),
          )
          .toList(),
    );
  }
}

class _DetailLine extends StatelessWidget {
  const _DetailLine({
    required this.label,
    required this.value,
  });

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: RichText(
        text: TextSpan(
          style: TextStyle(
            color: BrandConfig.textMutedOf(context),
            height: 1.4,
          ),
          children: [
            TextSpan(
              text: '$label: ',
              style: TextStyle(
                color: BrandConfig.textOf(context),
                fontWeight: FontWeight.w700,
              ),
            ),
            TextSpan(text: value),
          ],
        ),
      ),
    );
  }
}
