import 'package:flutter/material.dart';

import '../config/brand_config.dart';
import '../services/api_client.dart';
import '../services/mobile_data_service.dart';
import '../state/session_controller.dart';
import '../widgets/brand_backdrop.dart';
import 'provider_detail_screen.dart';
import 'request_create_screen.dart';
import 'site_shell_screen.dart';

class ProviderCatalogScreen extends StatefulWidget {
  const ProviderCatalogScreen({
    super.key,
    required this.sessionController,
    required this.dataService,
  });

  final SessionController sessionController;
  final MobileDataService dataService;

  @override
  State<ProviderCatalogScreen> createState() => _ProviderCatalogScreenState();
}

class _ProviderCatalogScreenState extends State<ProviderCatalogScreen> {
  final TextEditingController _queryController = TextEditingController();

  bool _loading = true;
  bool _loadingMore = false;
  String? _error;

  Map<String, dynamic> _bootstrapPayload = const {};
  List<Map<String, dynamic>> _providers = <Map<String, dynamic>>[];
  int _totalCount = 0;
  bool _hasMore = false;

  int? _selectedServiceTypeId;
  String _selectedCity = '';
  String _selectedDistrict = '';
  String _selectedSortBy = 'relevance';
  String _selectedMinRating = '';
  String _selectedMinReviews = '';

  @override
  void initState() {
    super.initState();
    _bootstrap();
  }

  @override
  void dispose() {
    _queryController.dispose();
    super.dispose();
  }

  Map<String, dynamic> get _searchPayload =>
      _bootstrapPayload['search'] is Map<String, dynamic>
          ? _bootstrapPayload['search'] as Map<String, dynamic>
          : const <String, dynamic>{};

  List<Map<String, dynamic>> get _serviceTypes =>
      _mapList(_searchPayload['service_types']);

  List<Map<String, dynamic>> get _sortChoices =>
      _mapList(_searchPayload['sort_choices']);

  List<Map<String, dynamic>> get _minRatingChoices =>
      _mapList(_searchPayload['min_rating_choices']);

  List<Map<String, dynamic>> get _minReviewChoices =>
      _mapList(_searchPayload['min_review_choices']);

  Map<String, List<String>> get _cityDistrictMap {
    final raw = _searchPayload['city_district_map'];
    if (raw is! Map) {
      return const <String, List<String>>{};
    }
    final normalized = <String, List<String>>{};
    for (final entry in raw.entries) {
      final key = entry.key.toString();
      final value = entry.value;
      if (value is List) {
        normalized[key] = value.map((item) => item.toString()).toList();
      } else {
        normalized[key] = <String>[];
      }
    }
    return normalized;
  }

  List<String> get _cityOptions => _cityDistrictMap.keys.toList();

  List<String> get _districtOptions {
    if (_selectedCity.isEmpty) {
      return const <String>[];
    }
    return _cityDistrictMap[_selectedCity] ?? const <String>[];
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
          '/',
          pageTitle: 'UstaBul',
        ),
      ),
    );
  }

  Future<void> _bootstrap() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final accessToken = await widget.sessionController.ensureAccessToken();
      final bootstrap = await widget.dataService.fetchMarketplaceBootstrap(
        accessToken: accessToken,
      );
      if (!mounted) {
        return;
      }
      setState(() {
        _bootstrapPayload = bootstrap;
      });
      await _loadProviders(reset: true);
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
        _loading = false;
      });
    }
  }

  Future<void> _loadProviders({required bool reset}) async {
    if (reset) {
      setState(() {
        _loading = true;
        _error = null;
      });
    } else {
      setState(() {
        _loadingMore = true;
        _error = null;
      });
    }

    try {
      final accessToken = await widget.sessionController.ensureAccessToken();
      final payload = await widget.dataService.fetchProviders(
        accessToken: accessToken,
        query: _queryController.text,
        serviceTypeId: _selectedServiceTypeId,
        city: _selectedCity,
        district: _selectedDistrict,
        sortBy: _selectedSortBy,
        minRating: _selectedMinRating.isEmpty
            ? null
            : double.tryParse(_selectedMinRating),
        minReviews: _selectedMinReviews.isEmpty
            ? null
            : int.tryParse(_selectedMinReviews),
        limit: 20,
        offset: reset ? 0 : _providers.length,
      );
      final nextProviders = _mapList(payload['results']);
      if (!mounted) {
        return;
      }
      setState(() {
        _providers = reset
            ? nextProviders
            : <Map<String, dynamic>>[
                ..._providers,
                ...nextProviders,
              ];
        _totalCount = (payload['count'] as num?)?.toInt() ?? _providers.length;
        _hasMore = payload['has_more'] == true;
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
          _loadingMore = false;
        });
      }
    }
  }

  List<Map<String, dynamic>> _mapList(dynamic rawValue) {
    if (rawValue is! List) {
      return const <Map<String, dynamic>>[];
    }
    return rawValue
        .whereType<Map>()
        .map(
          (item) => item.map(
            (key, value) => MapEntry(key.toString(), value),
          ),
        )
        .toList();
  }

  void _handleCityChanged(String? value) {
    final nextCity = value ?? '';
    final nextDistricts = _cityDistrictMap[nextCity] ?? const <String>[];
    setState(() {
      _selectedCity = nextCity;
      if (!nextDistricts.contains(_selectedDistrict)) {
        _selectedDistrict = '';
      }
    });
  }

  Future<void> _clearFilters() async {
    _queryController.clear();
    setState(() {
      _selectedServiceTypeId = null;
      _selectedCity = '';
      _selectedDistrict = '';
      _selectedSortBy = 'relevance';
      _selectedMinRating = '';
      _selectedMinReviews = '';
    });
    await _loadProviders(reset: true);
  }

  Future<void> _openProviderDetail(int providerId) async {
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

  Future<void> _openRequestCreate({
    int? preferredProviderId,
    String? preferredProviderName,
  }) async {
    final created = await Navigator.of(context).push<bool>(
      MaterialPageRoute<bool>(
        builder: (_) => RequestCreateScreen(
          sessionController: widget.sessionController,
          dataService: widget.dataService,
          preferredProviderId: preferredProviderId,
          preferredProviderName: preferredProviderName,
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
    return Scaffold(
      appBar: AppBar(
        title: const Text('Ustalar'),
      ),
      body: BrandBackdrop(
        child: _loading && _providers.isEmpty
            ? const Center(child: CircularProgressIndicator())
            : RefreshIndicator(
                onRefresh: () => _loadProviders(reset: true),
                child: ListView(
                  padding: const EdgeInsets.fromLTRB(16, 12, 16, 24),
                  children: [
                    const _HeroPanel(
                      title: 'Usta keşfet',
                      subtitle:
                          'Şehir, ilçe ve hizmet filtresiyle uygun ustaları inceleyin; ardından doğrudan talep oluşturun.',
                    ),
                    const SizedBox(height: 16),
                    Card(
                      child: Padding(
                        padding: const EdgeInsets.all(18),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              'Filtreler',
                              style: Theme.of(context)
                                  .textTheme
                                  .titleMedium
                                  ?.copyWith(fontWeight: FontWeight.w700),
                            ),
                            const SizedBox(height: 14),
                            TextField(
                              controller: _queryController,
                              decoration: const InputDecoration(
                                labelText: 'Usta veya hizmet ara',
                                prefixIcon: Icon(Icons.search_rounded),
                              ),
                            ),
                            const SizedBox(height: 12),
                            DropdownButtonFormField<int>(
                              key: ValueKey<int?>(_selectedServiceTypeId),
                              initialValue: _selectedServiceTypeId,
                              isExpanded: true,
                              items: [
                                const DropdownMenuItem<int>(
                                  value: null,
                                  child: Text('Tüm hizmetler'),
                                ),
                                ..._serviceTypes.map(
                                  (item) => DropdownMenuItem<int>(
                                    value: (item['id'] as num?)?.toInt(),
                                    child:
                                        Text((item['name'] ?? '').toString()),
                                  ),
                                ),
                              ],
                              onChanged: (value) {
                                setState(() {
                                  _selectedServiceTypeId = value;
                                });
                              },
                              decoration: const InputDecoration(
                                labelText: 'Hizmet türü',
                              ),
                            ),
                            const SizedBox(height: 12),
                            Column(
                              children: [
                                DropdownButtonFormField<String>(
                                  key: ValueKey<String>(_selectedCity),
                                  initialValue: _selectedCity.isEmpty
                                      ? null
                                      : _selectedCity,
                                  isExpanded: true,
                                  items: [
                                    const DropdownMenuItem<String>(
                                      value: null,
                                      child: Text('Şehir seçin'),
                                    ),
                                    ..._cityOptions.map(
                                      (item) => DropdownMenuItem<String>(
                                        value: item,
                                        child: Text(item),
                                      ),
                                    ),
                                  ],
                                  onChanged: _handleCityChanged,
                                  decoration: const InputDecoration(
                                    labelText: 'Şehir',
                                  ),
                                ),
                                const SizedBox(height: 12),
                                DropdownButtonFormField<String>(
                                  key: ValueKey<String>(
                                    '$_selectedCity|$_selectedDistrict',
                                  ),
                                  initialValue: _selectedDistrict.isEmpty
                                      ? null
                                      : _selectedDistrict,
                                  isExpanded: true,
                                  items: [
                                    const DropdownMenuItem<String>(
                                      value: null,
                                      child: Text('İlçe seçin'),
                                    ),
                                    ..._districtOptions.map(
                                      (item) => DropdownMenuItem<String>(
                                        value: item,
                                        child: Text(item),
                                      ),
                                    ),
                                  ],
                                  onChanged: (value) {
                                    setState(() {
                                      _selectedDistrict = value ?? '';
                                    });
                                  },
                                  decoration: const InputDecoration(
                                    labelText: 'İlçe',
                                  ),
                                ),
                              ],
                            ),
                            const SizedBox(height: 12),
                            Column(
                              children: [
                                DropdownButtonFormField<String>(
                                  key: ValueKey<String>(_selectedSortBy),
                                  initialValue: _selectedSortBy,
                                  isExpanded: true,
                                  items: _sortChoices
                                      .map(
                                        (item) => DropdownMenuItem<String>(
                                          value:
                                              (item['value'] ?? '').toString(),
                                          child: Text(
                                            (item['label'] ?? '').toString(),
                                          ),
                                        ),
                                      )
                                      .toList(),
                                  onChanged: (value) {
                                    setState(() {
                                      _selectedSortBy = value ?? 'relevance';
                                    });
                                  },
                                  decoration: const InputDecoration(
                                    labelText: 'Sıralama',
                                  ),
                                ),
                                const SizedBox(height: 12),
                                DropdownButtonFormField<String>(
                                  key: ValueKey<String>(_selectedMinRating),
                                  initialValue: _selectedMinRating.isEmpty
                                      ? null
                                      : _selectedMinRating,
                                  isExpanded: true,
                                  items: [
                                    const DropdownMenuItem<String>(
                                      value: null,
                                      child: Text('Puan fark etmez'),
                                    ),
                                    ..._minRatingChoices
                                        .where(
                                          (item) => (item['value'] ?? '')
                                              .toString()
                                              .isNotEmpty,
                                        )
                                        .map(
                                          (item) => DropdownMenuItem<String>(
                                            value: (item['value'] ?? '')
                                                .toString(),
                                            child: Text(
                                              (item['label'] ?? '').toString(),
                                            ),
                                          ),
                                        ),
                                  ],
                                  onChanged: (value) {
                                    setState(() {
                                      _selectedMinRating = value ?? '';
                                    });
                                  },
                                  decoration: const InputDecoration(
                                    labelText: 'Minimum puan',
                                  ),
                                ),
                              ],
                            ),
                            const SizedBox(height: 12),
                            DropdownButtonFormField<String>(
                              key: ValueKey<String>(_selectedMinReviews),
                              initialValue: _selectedMinReviews.isEmpty
                                  ? null
                                  : _selectedMinReviews,
                              isExpanded: true,
                              items: [
                                const DropdownMenuItem<String>(
                                  value: null,
                                  child: Text('Yorum sayısı fark etmez'),
                                ),
                                ..._minReviewChoices
                                    .where(
                                      (item) => (item['value'] ?? '')
                                          .toString()
                                          .isNotEmpty,
                                    )
                                    .map(
                                      (item) => DropdownMenuItem<String>(
                                        value: (item['value'] ?? '').toString(),
                                        child: Text(
                                            (item['label'] ?? '').toString()),
                                      ),
                                    ),
                              ],
                              onChanged: (value) {
                                setState(() {
                                  _selectedMinReviews = value ?? '';
                                });
                              },
                              decoration: const InputDecoration(
                                  labelText: 'Minimum yorum'),
                            ),
                            const SizedBox(height: 16),
                            Column(
                              crossAxisAlignment: CrossAxisAlignment.stretch,
                              children: [
                                FilledButton.icon(
                                  onPressed: () => _loadProviders(reset: true),
                                  icon: const Icon(Icons.search_rounded),
                                  label: const Text('Filtrele'),
                                ),
                                const SizedBox(height: 10),
                                FilledButton.tonalIcon(
                                  onPressed: _clearFilters,
                                  icon: const Icon(
                                    Icons.filter_alt_off_rounded,
                                  ),
                                  label: const Text('Temizle'),
                                ),
                              ],
                            ),
                          ],
                        ),
                      ),
                    ),
                    const SizedBox(height: 16),
                    if (_error != null)
                      _InlineError(
                        message: _error!,
                        onRetry: () => _loadProviders(reset: true),
                      ),
                    Padding(
                      padding: const EdgeInsets.only(bottom: 12),
                      child: Text(
                        'Toplam $_totalCount uygun usta bulundu.',
                        style:
                            TextStyle(color: BrandConfig.textMutedOf(context)),
                      ),
                    ),
                    if (_providers.isEmpty && !_loading)
                      const _EmptyPanel(
                        title: 'Uygun usta bulunamadı',
                        body:
                            'Filtreleri gevşetip yeniden arayabilir ya da doğrudan genel talep oluşturabilirsiniz.',
                      ),
                    for (final item in _providers)
                      _ProviderCard(
                        provider: item,
                        onOpenDetail: () => _openProviderDetail(
                            (item['id'] as num?)?.toInt() ?? 0),
                        onCreateRequest: () => _openRequestCreate(
                          preferredProviderId: (item['id'] as num?)?.toInt(),
                          preferredProviderName:
                              (item['full_name'] ?? '').toString(),
                        ),
                      ),
                    if (_loadingMore)
                      const Padding(
                        padding: EdgeInsets.only(top: 8),
                        child: Center(child: CircularProgressIndicator()),
                      ),
                    if (_hasMore && !_loadingMore)
                      Padding(
                        padding: const EdgeInsets.only(top: 8),
                        child: FilledButton.tonalIcon(
                          onPressed: () => _loadProviders(reset: false),
                          icon: const Icon(Icons.expand_more_rounded),
                          label: const Text('Daha fazla göster'),
                        ),
                      ),
                  ],
                ),
              ),
      ),
    );
  }
}

class _HeroPanel extends StatelessWidget {
  const _HeroPanel({
    required this.title,
    required this.subtitle,
  });

  final String title;
  final String subtitle;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BrandConfig.heroPanelDecorationOf(context),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            title,
            style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                  color: BrandConfig.textOf(context),
                  fontWeight: FontWeight.w800,
                ),
          ),
          const SizedBox(height: 8),
          Text(
            subtitle,
            style: TextStyle(
              color: BrandConfig.heroTextMutedOf(context),
              height: 1.45,
            ),
          ),
        ],
      ),
    );
  }
}

class _ProviderCard extends StatelessWidget {
  const _ProviderCard({
    required this.provider,
    required this.onOpenDetail,
    required this.onCreateRequest,
  });

  final Map<String, dynamic> provider;
  final Future<void> Function() onOpenDetail;
  final Future<void> Function() onCreateRequest;

  @override
  Widget build(BuildContext context) {
    final services = provider['service_types'] is List
        ? (provider['service_types'] as List)
            .map((item) => item.toString())
            .where((item) => item.isNotEmpty)
            .toList()
        : const <String>[];

    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      child: Padding(
        padding: const EdgeInsets.all(18),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        (provider['full_name'] ?? 'Usta').toString(),
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                        style:
                            Theme.of(context).textTheme.titleMedium?.copyWith(
                                  fontWeight: FontWeight.w700,
                                ),
                      ),
                      const SizedBox(height: 6),
                      Text(
                        '${(provider['city'] ?? '').toString()} / ${(provider['district'] ?? '').toString()}',
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                        style:
                            TextStyle(color: BrandConfig.textMutedOf(context)),
                      ),
                    ],
                  ),
                ),
                const SizedBox(width: 12),
                Container(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                  decoration: BoxDecoration(
                    color: BrandConfig.accentSoftOf(context),
                    borderRadius: BorderRadius.circular(999),
                  ),
                  child: Text(
                    '⭐ ${(provider['rating'] ?? 0).toString()}',
                    style: TextStyle(
                      color: BrandConfig.textOf(context),
                      fontSize: 12,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 10),
            Text(
              services.isEmpty ? 'Hizmet bilgisi yok.' : services.join(', '),
              style: TextStyle(
                color: BrandConfig.textMutedOf(context),
                height: 1.4,
              ),
            ),
            if (((provider['description'] ?? '').toString())
                .trim()
                .isNotEmpty) ...[
              const SizedBox(height: 10),
              Text(
                (provider['description'] ?? '').toString(),
                maxLines: 3,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                  color: BrandConfig.textOf(context),
                  height: 1.4,
                ),
              ),
            ],
            const SizedBox(height: 14),
            Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                FilledButton.tonal(
                  onPressed: onOpenDetail,
                  child: const Text('Detayı aç'),
                ),
                const SizedBox(height: 10),
                FilledButton(
                  onPressed: onCreateRequest,
                  child: const Text('Talep aç'),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

class _InlineError extends StatelessWidget {
  const _InlineError({
    required this.message,
    required this.onRetry,
  });

  final String message;
  final Future<void> Function() onRetry;

  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      color: BrandConfig.errorSurfaceOf(context),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          children: [
            Icon(
              Icons.error_outline_rounded,
              color: BrandConfig.errorTextOf(context),
            ),
            const SizedBox(width: 12),
            Expanded(child: Text(message)),
            TextButton(
              onPressed: onRetry,
              child: const Text('Tekrar dene'),
            ),
          ],
        ),
      ),
    );
  }
}

class _EmptyPanel extends StatelessWidget {
  const _EmptyPanel({
    required this.title,
    required this.body,
  });

  final String title;
  final String body;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          children: [
            Icon(
              Icons.search_off_rounded,
              size: 38,
              color: BrandConfig.textMutedOf(context),
            ),
            const SizedBox(height: 12),
            Text(
              title,
              style: Theme.of(context).textTheme.titleMedium?.copyWith(
                    fontWeight: FontWeight.w700,
                  ),
            ),
            const SizedBox(height: 8),
            Text(
              body,
              textAlign: TextAlign.center,
              style: TextStyle(color: BrandConfig.textMutedOf(context)),
            ),
          ],
        ),
      ),
    );
  }
}
