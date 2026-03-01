import 'package:flutter/material.dart';

import '../services/mobile_data_service.dart';
import '../state/session_controller.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({
    super.key,
    required this.sessionController,
    required this.dataService,
  });

  final SessionController sessionController;
  final MobileDataService dataService;

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  bool _loading = true;
  String? _error;
  Map<String, dynamic> _payload = const {};

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final accessToken = await widget.sessionController.ensureAccessToken();
      final session = widget.sessionController.session;
      if (session == null) {
        throw Exception('Oturum bulunamadi.');
      }
      final payload = session.isProvider
          ? await widget.dataService.fetchProviderDashboard(accessToken: accessToken)
          : await widget.dataService.fetchCustomerRequests(accessToken: accessToken);

      if (!mounted) {
        return;
      }
      setState(() {
        _payload = payload;
      });
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

  @override
  Widget build(BuildContext context) {
    final session = widget.sessionController.session;
    if (session == null) {
      return const SizedBox.shrink();
    }
    return Scaffold(
      appBar: AppBar(
        title: Text(session.isProvider ? 'Usta Paneli' : 'Musteri Taleplerim'),
        actions: [
          IconButton(
            onPressed: _loading ? null : _load,
            icon: const Icon(Icons.refresh),
            tooltip: 'Yenile',
          ),
          IconButton(
            onPressed: widget.sessionController.logout,
            icon: const Icon(Icons.logout),
            tooltip: 'Cikis',
          ),
        ],
      ),
      body: RefreshIndicator(
        onRefresh: _load,
        child: _buildBody(session.isProvider),
      ),
    );
  }

  Widget _buildBody(bool isProvider) {
    if (_loading) {
      return const Center(child: CircularProgressIndicator());
    }
    if (_error != null) {
      return ListView(
        children: [
          const SizedBox(height: 120),
          Center(
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 24),
              child: Text(_error!, textAlign: TextAlign.center),
            ),
          ),
        ],
      );
    }
    return isProvider ? _buildProviderBody() : _buildCustomerBody();
  }

  Widget _buildCustomerBody() {
    final results = (_payload['results'] as List?) ?? const [];
    if (results.isEmpty) {
      return ListView(
        children: const [
          SizedBox(height: 120),
          Center(child: Text('Henuz talep bulunmuyor.')),
        ],
      );
    }
    return ListView.separated(
      padding: const EdgeInsets.all(16),
      itemBuilder: (context, index) {
        final item = results[index];
        if (item is! Map) {
          return const SizedBox.shrink();
        }
        return Card(
          child: ListTile(
            title: Text('#${item['id']} - ${item['service_type'] ?? ''}'),
            subtitle: Text(
              '${item['city'] ?? ''}/${item['district'] ?? ''}\n'
              'Durum: ${item['status'] ?? ''} | Okunmamis: ${item['unread_messages'] ?? 0}',
            ),
            isThreeLine: true,
          ),
        );
      },
      separatorBuilder: (_, __) => const SizedBox(height: 8),
      itemCount: results.length,
    );
  }

  Widget _buildProviderBody() {
    final snapshot = _payload['snapshot'] as Map?;
    final threads = (_payload['active_threads'] as List?) ?? const [];
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text('Canli Ozet', style: TextStyle(fontWeight: FontWeight.w700)),
                const SizedBox(height: 8),
                Text('Bekleyen teklif: ${snapshot?['pending_offers_count'] ?? 0}'),
                Text('Bekleyen randevu: ${snapshot?['pending_appointments_count'] ?? 0}'),
                Text('Okunmamis mesaj: ${snapshot?['unread_messages_count'] ?? 0}'),
              ],
            ),
          ),
        ),
        const SizedBox(height: 12),
        const Text(
          'Aktif Isler',
          style: TextStyle(fontSize: 18, fontWeight: FontWeight.w700),
        ),
        const SizedBox(height: 8),
        if (threads.isEmpty)
          const Card(
            child: Padding(
              padding: EdgeInsets.all(16),
              child: Text('Aktif is bulunmuyor.'),
            ),
          ),
        for (final item in threads)
          if (item is Map)
            Card(
              child: ListTile(
                title: Text('#${item['id']} - ${item['service_type'] ?? ''}'),
                subtitle: Text(
                  '${item['city'] ?? ''}/${item['district'] ?? ''}\n'
                  'Musteri: ${item['customer_name'] ?? ''} | Okunmamis: ${item['unread_messages'] ?? 0}',
                ),
                isThreeLine: true,
              ),
            ),
      ],
    );
  }
}
