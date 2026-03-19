import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';

import '../config/brand_config.dart';
import '../services/api_client.dart';
import '../services/mobile_data_service.dart';
import '../state/session_controller.dart';
import '../widgets/brand_backdrop.dart';
import 'request_create_screen.dart';
import 'site_shell_screen.dart';

class ProviderDetailScreen extends StatefulWidget {
  const ProviderDetailScreen({
    super.key,
    required this.sessionController,
    required this.dataService,
    required this.providerId,
  });

  final SessionController sessionController;
  final MobileDataService dataService;
  final int providerId;

  @override
  State<ProviderDetailScreen> createState() => _ProviderDetailScreenState();
}

class _ProviderDetailScreenState extends State<ProviderDetailScreen> {
  bool _loading = true;
  String? _error;
  Map<String, dynamic> _payload = const {};

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
          '/usta/${widget.providerId}/',
          pageTitle: 'Usta Detayı',
        ),
      ),
    );
  }

  Map<String, dynamic> get _provider =>
      _payload['provider'] is Map<String, dynamic>
          ? _payload['provider'] as Map<String, dynamic>
          : const <String, dynamic>{};

  List<Map<String, dynamic>> get _recentRatings {
    final raw = _payload['recent_ratings'];
    if (raw is! List) {
      return const <Map<String, dynamic>>[];
    }
    return raw
        .whereType<Map>()
        .map(
            (item) => item.map((key, value) => MapEntry(key.toString(), value)))
        .toList();
  }

  Future<void> _load() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final accessToken = await widget.sessionController.ensureAccessToken();
      final payload = await widget.dataService.fetchProviderDetail(
        accessToken: accessToken,
        providerId: widget.providerId,
      );
      if (!mounted) {
        return;
      }
      setState(() {
        _payload = payload;
      });
    } catch (error) {
      if (error is ApiException && error.statusCode == 404) {
        await _openWebFallback();
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

  Future<void> _launchExternal(String rawUri) async {
    final uri = Uri.tryParse(rawUri);
    if (uri == null) {
      return;
    }
    final didLaunch =
        await launchUrl(uri, mode: LaunchMode.externalApplication);
    if (!didLaunch && mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('İlgili uygulama cihazda açılamadı.')),
      );
    }
  }

  String _buildWhatsAppUrl(String rawPhone) {
    final digits = rawPhone.replaceAll(RegExp(r'\D'), '');
    if (digits.isEmpty) {
      return '';
    }
    String normalized = digits;
    if (normalized.startsWith('00')) {
      normalized = normalized.substring(2);
    } else if (normalized.startsWith('0') && normalized.length == 11) {
      normalized = '90${normalized.substring(1)}';
    } else if (normalized.length == 10) {
      normalized = '90$normalized';
    }
    final message = Uri.encodeComponent(
      'Merhaba, UstaBul üzerinden ulaşıyorum.',
    );
    return 'https://wa.me/$normalized?text=$message';
  }

  Future<void> _openRequestCreate() async {
    final created = await Navigator.of(context).push<bool>(
      MaterialPageRoute<bool>(
        builder: (_) => RequestCreateScreen(
          sessionController: widget.sessionController,
          dataService: widget.dataService,
          preferredProviderId: widget.providerId,
          preferredProviderName: (_provider['full_name'] ?? '').toString(),
        ),
      ),
    );
    if (created == true && mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Talebiniz oluşturuldu.')),
      );
    }
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

    if (_error != null) {
      return Scaffold(
        appBar: AppBar(title: const Text('Usta detayı')),
        body: BrandBackdrop(
          child: Center(
            child: Padding(
              padding: const EdgeInsets.all(24),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(
                    Icons.error_outline_rounded,
                    color: BrandConfig.textMutedOf(context),
                    size: 40,
                  ),
                  const SizedBox(height: 12),
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

    final services = _provider['service_types'] is List
        ? (_provider['service_types'] as List)
            .map((item) => item.toString())
            .where((item) => item.isNotEmpty)
            .toList()
        : const <String>[];
    final phone = (_provider['phone'] ?? '').toString();
    final whatsappUrl = phone.isEmpty ? '' : _buildWhatsAppUrl(phone);

    return Scaffold(
      appBar: AppBar(title: const Text('Usta detayı')),
      body: BrandBackdrop(
        child: RefreshIndicator(
          onRefresh: _load,
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
                      (_provider['full_name'] ?? 'Usta').toString(),
                      style:
                          Theme.of(context).textTheme.headlineSmall?.copyWith(
                                color: BrandConfig.text,
                                fontWeight: FontWeight.w800,
                              ),
                    ),
                    const SizedBox(height: 8),
                    Text(
                      '${(_provider['city'] ?? '').toString()} / ${(_provider['district'] ?? '').toString()}',
                      style: TextStyle(
                        color: BrandConfig.heroTextMutedOf(context),
                      ),
                    ),
                    const SizedBox(height: 8),
                    Text(
                      '⭐ ${(_provider['rating'] ?? 0).toString()} · ${(_provider['ratings_count'] ?? 0).toString()} değerlendirme',
                      style: TextStyle(
                        color: BrandConfig.heroTextMutedOf(context),
                      ),
                    ),
                    const SizedBox(height: 16),
                    Row(
                      children: [
                        if (phone.isNotEmpty)
                          Expanded(
                            child: FilledButton.tonalIcon(
                              onPressed: () => _launchExternal('tel:$phone'),
                              icon: const Icon(Icons.phone_outlined),
                              label: const Text('Ara'),
                            ),
                          ),
                        if (phone.isNotEmpty) const SizedBox(width: 12),
                        if (whatsappUrl.isNotEmpty)
                          Expanded(
                            child: FilledButton.tonalIcon(
                              onPressed: () => _launchExternal(whatsappUrl),
                              icon:
                                  const Icon(Icons.chat_bubble_outline_rounded),
                              label: const Text('WhatsApp'),
                            ),
                          ),
                      ],
                    ),
                    const SizedBox(height: 12),
                    FilledButton.icon(
                      onPressed: _openRequestCreate,
                      icon: const Icon(Icons.send_rounded),
                      label: const Text('Bu ustaya talep aç'),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 16),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(18),
                  child: Row(
                    children: [
                      Expanded(
                        child: _StatBox(
                          label: 'Tamamlanan iş',
                          value: '${_payload['completed_jobs'] ?? 0}',
                        ),
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: _StatBox(
                          label: 'Onaylı teklif',
                          value: '${_payload['successful_quotes'] ?? 0}',
                        ),
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: _StatBox(
                          label: 'Durum',
                          value: _provider['is_available'] == true
                              ? 'Müsait'
                              : 'Kapalı',
                        ),
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 16),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(18),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Hizmet alanları',
                        style:
                            Theme.of(context).textTheme.titleMedium?.copyWith(
                                  fontWeight: FontWeight.w700,
                                ),
                      ),
                      const SizedBox(height: 12),
                      if (services.isEmpty)
                        Text(
                          'Hizmet alanı bilgisi yok.',
                          style: TextStyle(
                            color: BrandConfig.textMutedOf(context),
                          ),
                        )
                      else
                        Wrap(
                          spacing: 8,
                          runSpacing: 8,
                          children: services
                              .map(
                                (item) => Chip(
                                  label: Text(item),
                                  backgroundColor:
                                      BrandConfig.surfaceOf(context),
                                  side: BorderSide(
                                    color: BrandConfig.borderOf(context),
                                  ),
                                ),
                              )
                              .toList(),
                        ),
                    ],
                  ),
                ),
              ),
              if (((_provider['description'] ?? '').toString())
                  .trim()
                  .isNotEmpty) ...[
                const SizedBox(height: 16),
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(18),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          'Usta açıklaması',
                          style:
                              Theme.of(context).textTheme.titleMedium?.copyWith(
                                    fontWeight: FontWeight.w700,
                                  ),
                        ),
                        const SizedBox(height: 10),
                        Text(
                          (_provider['description'] ?? '').toString(),
                          style: TextStyle(
                            color: BrandConfig.textMutedOf(context),
                            height: 1.45,
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              ],
              const SizedBox(height: 16),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(18),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Müşteri yorumları',
                        style:
                            Theme.of(context).textTheme.titleMedium?.copyWith(
                                  fontWeight: FontWeight.w700,
                                ),
                      ),
                      const SizedBox(height: 12),
                      if (_recentRatings.isEmpty)
                        Text(
                          'Henüz yorum bulunmuyor.',
                          style: TextStyle(
                            color: BrandConfig.textMutedOf(context),
                          ),
                        ),
                      for (final item in _recentRatings)
                        Container(
                          margin: const EdgeInsets.only(bottom: 12),
                          padding: const EdgeInsets.all(14),
                          decoration: BoxDecoration(
                            color: BrandConfig.surfaceAltOf(context),
                            borderRadius: BorderRadius.circular(18),
                          ),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Row(
                                children: [
                                  Expanded(
                                    child: Text(
                                      (item['customer_username'] ?? '')
                                          .toString(),
                                      style: TextStyle(
                                        color: BrandConfig.textOf(context),
                                        fontWeight: FontWeight.w700,
                                      ),
                                    ),
                                  ),
                                  Text(
                                    '${item['score'] ?? 0}/5',
                                    style: TextStyle(
                                      color: BrandConfig.textMutedOf(context),
                                    ),
                                  ),
                                ],
                              ),
                              const SizedBox(height: 8),
                              Text(
                                ((item['comment'] ?? '').toString())
                                        .trim()
                                        .isEmpty
                                    ? 'Yorum bırakılmadı.'
                                    : (item['comment'] ?? '').toString(),
                                style: TextStyle(
                                  color: BrandConfig.textMutedOf(context),
                                  height: 1.4,
                                ),
                              ),
                            ],
                          ),
                        ),
                    ],
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _StatBox extends StatelessWidget {
  const _StatBox({
    required this.label,
    required this.value,
  });

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: BrandConfig.surfaceAltOf(context),
        borderRadius: BorderRadius.circular(18),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            label,
            style: TextStyle(color: BrandConfig.textMutedOf(context)),
          ),
          const SizedBox(height: 8),
          Text(
            value,
            style: Theme.of(context).textTheme.titleLarge?.copyWith(
                  fontWeight: FontWeight.w800,
                ),
          ),
        ],
      ),
    );
  }
}
