import 'package:flutter/material.dart';

import '../config/brand_config.dart';
import '../services/api_client.dart';
import '../services/mobile_data_service.dart';
import '../state/session_controller.dart';
import '../widgets/brand_backdrop.dart';
import 'site_shell_screen.dart';

class RequestCreateScreen extends StatefulWidget {
  const RequestCreateScreen({
    super.key,
    required this.sessionController,
    required this.dataService,
    this.preferredProviderId,
    this.preferredProviderName,
  });

  final SessionController sessionController;
  final MobileDataService dataService;
  final int? preferredProviderId;
  final String? preferredProviderName;

  @override
  State<RequestCreateScreen> createState() => _RequestCreateScreenState();
}

class _RequestCreateScreenState extends State<RequestCreateScreen> {
  final _nameController = TextEditingController();
  final _phoneController = TextEditingController();
  final _detailsController = TextEditingController();

  bool _loading = true;
  bool _submitting = false;
  String? _error;
  Map<String, dynamic> _bootstrapPayload = const {};

  int? _selectedServiceTypeId;
  String _selectedCity = '';
  String _selectedDistrict = '';

  @override
  void initState() {
    super.initState();
    _loadBootstrap();
  }

  @override
  void dispose() {
    _nameController.dispose();
    _phoneController.dispose();
    _detailsController.dispose();
    super.dispose();
  }

  Map<String, dynamic> get _requestForm =>
      _bootstrapPayload['request_form'] is Map<String, dynamic>
          ? _bootstrapPayload['request_form'] as Map<String, dynamic>
          : const <String, dynamic>{};

  Map<String, dynamic> get _searchPayload =>
      _bootstrapPayload['search'] is Map<String, dynamic>
          ? _bootstrapPayload['search'] as Map<String, dynamic>
          : const <String, dynamic>{};

  Map<String, dynamic>? get _preferredProvider =>
      _requestForm['preferred_provider'] is Map<String, dynamic>
          ? _requestForm['preferred_provider'] as Map<String, dynamic>
          : null;

  bool get _isPreferredProviderMode => _preferredProvider != null;

  List<Map<String, dynamic>> get _serviceTypes =>
      _mapList(_requestForm['service_types']);

  Map<String, List<String>> get _cityDistrictMap {
    final raw = _searchPayload['city_district_map'];
    if (raw is! Map) {
      return const <String, List<String>>{};
    }
    final normalized = <String, List<String>>{};
    for (final entry in raw.entries) {
      final key = entry.key.toString();
      if (entry.value is List) {
        normalized[key] =
            (entry.value as List).map((item) => item.toString()).toList();
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
          '/talep-formu/',
          pageTitle: 'Talep Formu',
        ),
      ),
    );
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

  Future<void> _loadBootstrap() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final accessToken = await widget.sessionController.ensureAccessToken();
      final payload = await widget.dataService.fetchMarketplaceBootstrap(
        accessToken: accessToken,
        preferredProviderId: widget.preferredProviderId,
      );
      final requestForm = payload['request_form'];
      final initial = requestForm is Map ? requestForm['initial'] : null;
      if (!mounted) {
        return;
      }
      setState(() {
        _bootstrapPayload = payload;
        if (initial is Map) {
          _nameController.text = (initial['customer_name'] ?? '').toString();
          _phoneController.text = (initial['customer_phone'] ?? '').toString();
          _selectedCity = (initial['city'] ?? '').toString();
          _selectedDistrict = (initial['district'] ?? '').toString();
          _selectedServiceTypeId =
              (initial['service_type_id'] as num?)?.toInt();
        }
      });
      _ensureDistrictConsistency();
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

  void _ensureDistrictConsistency() {
    final districts = _cityDistrictMap[_selectedCity] ?? const <String>[];
    if (!districts.contains(_selectedDistrict)) {
      _selectedDistrict = '';
    }
  }

  Future<void> _submit() async {
    FocusScope.of(context).unfocus();

    if (_nameController.text.trim().isEmpty ||
        _phoneController.text.trim().isEmpty ||
        _selectedServiceTypeId == null ||
        _selectedCity.isEmpty ||
        _selectedDistrict.isEmpty ||
        _detailsController.text.trim().isEmpty) {
      setState(() {
        _error = 'Lütfen tüm zorunlu alanları doldurun.';
      });
      return;
    }

    setState(() {
      _submitting = true;
      _error = null;
    });

    try {
      final accessToken = await widget.sessionController.ensureAccessToken();
      final payload = await widget.dataService.createRequest(
        accessToken: accessToken,
        customerName: _nameController.text.trim(),
        customerPhone: _phoneController.text.trim(),
        serviceTypeId: _selectedServiceTypeId!,
        city: _selectedCity,
        district: _selectedDistrict,
        details: _detailsController.text.trim(),
        preferredProviderId: widget.preferredProviderId,
      );
      if (!mounted) {
        return;
      }
      final message =
          (payload['message'] ?? 'Talebiniz oluşturuldu.').toString();
      ScaffoldMessenger.of(context)
        ..hideCurrentSnackBar()
        ..showSnackBar(SnackBar(content: Text(message)));
      Navigator.of(context).pop(true);
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
          _submitting = false;
        });
      }
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

    return Scaffold(
      appBar: AppBar(
        title: const Text('Talep oluştur'),
      ),
      body: BrandBackdrop(
        child: ListView(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 24),
          children: [
            if (_isPreferredProviderMode)
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(18),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Seçili usta',
                        style:
                            Theme.of(context).textTheme.titleMedium?.copyWith(
                                  fontWeight: FontWeight.w700,
                                ),
                      ),
                      const SizedBox(height: 8),
                      Text(
                        (_preferredProvider?['full_name'] ??
                                widget.preferredProviderName ??
                                '')
                            .toString(),
                        style: TextStyle(
                          color: BrandConfig.textOf(context),
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      const SizedBox(height: 6),
                      Text(
                        '${(_preferredProvider?['city'] ?? '').toString()} / ${(_preferredProvider?['district'] ?? '').toString()}',
                        style:
                            TextStyle(color: BrandConfig.textMutedOf(context)),
                      ),
                      const SizedBox(height: 8),
                      Text(
                        'Bu modda şehir ve ilçe sabittir. Hizmet seçimi sadece bu ustanın sunduğu alanlarla sınırlıdır.',
                        style: TextStyle(
                          color: BrandConfig.textMutedOf(context),
                          height: 1.4,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            if (_isPreferredProviderMode) const SizedBox(height: 16),
            Card(
              child: Padding(
                padding: const EdgeInsets.all(20),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Talep bilgileri',
                      style: Theme.of(context).textTheme.titleMedium?.copyWith(
                            fontWeight: FontWeight.w700,
                          ),
                    ),
                    const SizedBox(height: 16),
                    TextField(
                      controller: _nameController,
                      decoration: const InputDecoration(
                        labelText: 'Ad Soyad',
                        prefixIcon: Icon(Icons.person_outline_rounded),
                      ),
                    ),
                    const SizedBox(height: 12),
                    TextField(
                      controller: _phoneController,
                      keyboardType: TextInputType.phone,
                      decoration: const InputDecoration(
                        labelText: 'Telefon',
                        prefixIcon: Icon(Icons.phone_outlined),
                      ),
                    ),
                    const SizedBox(height: 12),
                    DropdownButtonFormField<int>(
                      key: ValueKey<int?>(_selectedServiceTypeId),
                      initialValue: _selectedServiceTypeId,
                      items: _serviceTypes
                          .map(
                            (item) => DropdownMenuItem<int>(
                              value: (item['id'] as num?)?.toInt(),
                              child: Text((item['name'] ?? '').toString()),
                            ),
                          )
                          .toList(),
                      onChanged: (value) {
                        setState(() {
                          _selectedServiceTypeId = value;
                        });
                      },
                      decoration: const InputDecoration(
                        labelText: 'İstenen hizmet',
                      ),
                    ),
                    const SizedBox(height: 12),
                    Row(
                      children: [
                        Expanded(
                          child: DropdownButtonFormField<String>(
                            key: ValueKey<String>(_selectedCity),
                            initialValue:
                                _selectedCity.isEmpty ? null : _selectedCity,
                            items: _cityOptions
                                .map(
                                  (item) => DropdownMenuItem<String>(
                                    value: item,
                                    child: Text(item),
                                  ),
                                )
                                .toList(),
                            onChanged: _isPreferredProviderMode
                                ? null
                                : (value) {
                                    setState(() {
                                      _selectedCity = value ?? '';
                                      _ensureDistrictConsistency();
                                    });
                                  },
                            decoration:
                                const InputDecoration(labelText: 'Şehir'),
                          ),
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: DropdownButtonFormField<String>(
                            key: ValueKey<String>(
                              '$_selectedCity|$_selectedDistrict',
                            ),
                            initialValue: _selectedDistrict.isEmpty
                                ? null
                                : _selectedDistrict,
                            items: _districtOptions
                                .map(
                                  (item) => DropdownMenuItem<String>(
                                    value: item,
                                    child: Text(item),
                                  ),
                                )
                                .toList(),
                            onChanged: _isPreferredProviderMode
                                ? null
                                : (value) {
                                    setState(() {
                                      _selectedDistrict = value ?? '';
                                    });
                                  },
                            decoration:
                                const InputDecoration(labelText: 'İlçe'),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 12),
                    TextField(
                      controller: _detailsController,
                      minLines: 4,
                      maxLines: 7,
                      decoration: const InputDecoration(
                        labelText: 'Arıza / iş detayı',
                        alignLabelWithHint: true,
                      ),
                    ),
                    const SizedBox(height: 10),
                    Text(
                      'Sorunu mümkün olduğunca net anlatın. Böylece doğru ustalara daha hızlı iletilir.',
                      style: TextStyle(color: BrandConfig.textMutedOf(context)),
                    ),
                    if (_error != null) ...[
                      const SizedBox(height: 14),
                      Text(
                        _error!,
                        style:
                            TextStyle(color: BrandConfig.errorTextOf(context)),
                      ),
                    ],
                    const SizedBox(height: 18),
                    FilledButton.icon(
                      onPressed: _submitting ? null : _submit,
                      icon: _submitting
                          ? const SizedBox(
                              width: 16,
                              height: 16,
                              child: CircularProgressIndicator(strokeWidth: 2),
                            )
                          : const Icon(Icons.send_rounded),
                      label:
                          Text(_submitting ? 'Gönderiliyor' : 'Talebi gönder'),
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
