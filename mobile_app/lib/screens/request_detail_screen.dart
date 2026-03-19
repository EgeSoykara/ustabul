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

class _RequestDetailScreenState extends State<RequestDetailScreen> {
  bool _loading = true;
  bool _actionLoading = false;
  String? _error;
  Map<String, dynamic> _payload = const {};

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
    _load();
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

  Future<void> _load() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final accessToken = await widget.sessionController.ensureAccessToken();
      final payload = await widget.dataService.fetchRequestDetail(
        accessToken: accessToken,
        requestId: widget.requestId,
      );
      if (!mounted) {
        return;
      }
      setState(() {
        _payload = payload;
      });
    } catch (error) {
      if (error is ApiException && error.statusCode == 404) {
        await _handleMissingNativeEndpoint();
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
          _loading = false;
        });
      }
    }
  }

  Future<void> _performAndPop(
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
      Navigator.of(context).pop(true);
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

  Future<String?> _promptForShortNote({
    required String title,
    required String hintText,
  }) async {
    final controller = TextEditingController();
    final result = await showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: BrandConfig.surfaceOf(context),
        title: Text(title),
        content: TextField(
          controller: controller,
          autofocus: true,
          maxLength:
              ((_payload['short_note_max_length'] as num?)?.toInt() ?? 100),
          minLines: 1,
          maxLines: 3,
          decoration: InputDecoration(hintText: hintText),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Vazgeç'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(controller.text.trim()),
            child: const Text('Devam et'),
          ),
        ],
      ),
    );
    controller.dispose();
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
    final noteController = TextEditingController();
    final note = await showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: BrandConfig.surfaceOf(context),
        title: const Text('Randevu notu'),
        content: TextField(
          controller: noteController,
          maxLength:
              ((_payload['short_note_max_length'] as num?)?.toInt() ?? 100),
          minLines: 1,
          maxLines: 3,
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
            onPressed: () =>
                Navigator.of(context).pop(noteController.text.trim()),
            child: const Text('Gönder'),
          ),
        ],
      ),
    );
    noteController.dispose();
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
            Container(
              padding: const EdgeInsets.all(20),
              decoration: BrandConfig.heroPanelDecorationOf(context),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    (_request['service_type'] ?? 'Talep').toString(),
                    style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                          color: BrandConfig.text,
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
                          value: (_request['status'] ?? '').toString(),
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
                        value: (_appointment?['status'] ?? '').toString(),
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
                        value: (_providerOffer?['status'] ?? '').toString(),
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
