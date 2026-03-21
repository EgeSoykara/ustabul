import 'package:flutter/material.dart';
import 'dart:async';

import 'package:url_launcher/url_launcher.dart';

import '../config/brand_config.dart';
import '../services/api_client.dart';
import '../services/mobile_data_service.dart';
import '../services/theme_storage.dart';
import '../state/session_controller.dart';
import '../state/theme_controller.dart';
import '../widgets/brand_backdrop.dart';
import 'provider_catalog_screen.dart';
import 'request_detail_screen.dart';
import 'request_thread_screen.dart';
import 'request_create_screen.dart';
import 'site_shell_screen.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({
    super.key,
    required this.sessionController,
    required this.dataService,
    required this.themeController,
  });

  final SessionController sessionController;
  final MobileDataService dataService;
  final ThemeController themeController;

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> with WidgetsBindingObserver {
  static const int _requestsPageSize = 20;
  static const int _agreementsPageSize = 20;
  static const int _notificationsPageSize = 20;
  static const Duration _refreshTickInterval = Duration(seconds: 5);
  static const Duration _providerDashboardRefreshInterval =
      Duration(seconds: 5);
  static const Duration _customerDashboardRefreshInterval =
      Duration(seconds: 8);
  static const Duration _notificationsRefreshInterval = Duration(seconds: 8);

  int _currentIndex = 0;
  String _customerRequestFilter = 'active';
  String _providerWorkFilter = 'queue';
  final Set<String> _runningProviderActionKeys = <String>{};
  Timer? _autoRefreshTimer;
  Timer? _liveUpdateTimer;
  StreamSubscription<Map<String, dynamic>>? _liveUpdatesSubscription;
  AppLifecycleState _appLifecycleState = AppLifecycleState.resumed;
  DateTime? _lastDashboardSyncAt;
  DateTime? _lastNotificationSyncAt;
  bool _dashboardRequestInFlight = false;
  bool _notificationsRequestInFlight = false;
  String _providerDashboardVersion = '';
  String _customerRequestsVersion = '';
  String _customerAgreementsVersion = '';
  String _notificationsVersion = '';
  String? _liveUpdateMessage;
  int? _liveUpdateTabIndex;

  bool _dashboardLoading = true;
  String? _dashboardError;
  Map<String, dynamic> _dashboardPayload = const {};

  bool _notificationsLoading = false;
  String? _notificationsError;
  Map<String, dynamic> _notificationsPayload = const {};
  String _notificationCategory = 'all';
  bool _notificationsFallbackToWeb = false;
  bool _customerRequestsLoadingMore = false;
  bool _customerRequestsTabLoadingMore = false;
  bool _customerAgreementsLoadingMore = false;
  bool _providerAgreementsLoadingMore = false;
  bool _notificationsLoadingMore = false;

  bool _preferencesLoading = false;
  bool _preferencesSaving = false;
  String? _preferencesError;
  Map<String, dynamic> _notificationPreferences = const {};
  bool _notificationPreferencesFallbackToWeb = false;
  List<Map<String, dynamic>> _customerRequestsTabItems =
      const <Map<String, dynamic>>[];
  int _customerRequestsTabCount = 0;
  String _customerRequestsTabFilter = 'active';
  bool _customerRequestsTabLoaded = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _subscribeToLiveUpdates();
    _startAutoRefresh();
    _loadDashboard();
  }

  @override
  void dispose() {
    _autoRefreshTimer?.cancel();
    _liveUpdateTimer?.cancel();
    _liveUpdatesSubscription?.cancel();
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    _appLifecycleState = state;
    if (state == AppLifecycleState.resumed) {
      _refreshVisibleTabSilently(force: true);
    }
  }

  bool get _isProvider => widget.sessionController.session?.isProvider == true;

  Map<String, dynamic> get _sessionSnapshot =>
      widget.sessionController.session?.snapshot ?? const {};

  List<Map<String, dynamic>> get _customerRequests =>
      _mapList(_dashboardPayload['results']);

  Map<String, dynamic> get _customerSummary =>
      _dashboardPayload['summary'] is Map<String, dynamic>
          ? _dashboardPayload['summary'] as Map<String, dynamic>
          : const <String, dynamic>{};

  int get _customerRequestCount =>
      _summaryCount(_customerSummary, 'count', _customerRequests.length);

  int get _customerActiveCount =>
      _summaryCount(_customerSummary, 'active_count', _customerRequests.length);

  int get _customerDecisionCount =>
      _summaryCount(_customerSummary, 'decision_count', 0);

  int get _customerInProgressCount =>
      _summaryCount(_customerSummary, 'in_progress_count', 0);

  int get _customerWaitingCount =>
      _summaryCount(_customerSummary, 'waiting_count', 0);

  List<Map<String, dynamic>> get _customerAgreements =>
      _mapList(_dashboardPayload['agreements']);

  int get _customerAgreementCount {
    final rawCount = _dashboardPayload['agreements_count'];
    if (rawCount is num) {
      return rawCount.toInt();
    }
    return _customerAgreements.length;
  }

  List<Map<String, dynamic>> get _providerPendingOffers =>
      _mapList(_dashboardPayload['pending_offers']);

  List<Map<String, dynamic>> get _providerWaitingSelection =>
      _mapList(_dashboardPayload['waiting_customer_selection']);

  List<Map<String, dynamic>> get _providerActiveThreads =>
      _mapList(_dashboardPayload['active_threads']);

  List<Map<String, dynamic>> get _providerPendingAppointments =>
      _mapList(_dashboardPayload['pending_appointments']);

  List<Map<String, dynamic>> get _providerAgreements =>
      _mapList(_dashboardPayload['agreements']);

  int get _providerAgreementCount => _summaryCount(
      _providerSummary, 'agreements_count', _providerAgreements.length);

  bool get _customerAgreementsHasMore =>
      _customerAgreements.length < _customerAgreementCount;

  bool get _customerRequestsHasMore =>
      _customerRequests.length < _customerRequestCount;

  bool get _providerAgreementsHasMore =>
      _providerAgreements.length < _providerAgreementCount;

  bool get _notificationsHasMore {
    final count = (_notificationsPayload['count'] as num?)?.toInt() ?? 0;
    final loaded = _mapList(_notificationsPayload['results']).length;
    return loaded < count;
  }

  Map<String, dynamic> get _providerSummary =>
      _dashboardPayload['summary'] is Map<String, dynamic>
          ? _dashboardPayload['summary'] as Map<String, dynamic>
          : const <String, dynamic>{};

  List<Map<String, dynamic>> get _messageThreads {
    if (_isProvider) {
      return _providerActiveThreads;
    }
    return _customerRequests
        .where((item) => (item['status'] ?? '').toString() == 'matched')
        .toList();
  }

  List<Map<String, dynamic>> get _customerVisibleRequests {
    if (_customerRequestFilter == 'history') {
      return _customerAgreements;
    }
    return _customerRequestsTabItems
        .where(
          (item) => _matchesCustomerRequestFilter(item, _customerRequestFilter),
        )
        .toList();
  }

  int get _customerRequestsTabActiveCount => _customerRequestsTabItems
      .where((item) => _matchesCustomerRequestFilter(item, 'active'))
      .length;

  int get _customerRequestsTabDecisionCount => _customerRequestsTabItems
      .where((item) => _matchesCustomerRequestFilter(item, 'decision'))
      .length;

  int get _customerRequestsTabInProgressCount => _customerRequestsTabItems
      .where((item) => _matchesCustomerRequestFilter(item, 'in_progress'))
      .length;

  bool get _useCustomerRequestsTabMetrics => _customerRequestsTabLoaded;

  List<Map<String, dynamic>> get _customerDashboardRequests =>
      _useCustomerRequestsTabMetrics
          ? _customerRequestsTabItems
          : _customerRequests;

  int get _customerDashboardRequestCount => _useCustomerRequestsTabMetrics
      ? _customerRequestsTabActiveCount
      : _customerRequests
          .where((item) => _matchesCustomerRequestFilter(item, 'active'))
          .length;

  int get _customerDashboardActiveCount => _useCustomerRequestsTabMetrics
      ? _customerRequestsTabActiveCount
      : _customerActiveCount;

  int get _customerDashboardDecisionCount => _useCustomerRequestsTabMetrics
      ? _customerRequestsTabDecisionCount
      : _customerDecisionCount;

  int get _customerDashboardInProgressCount => _useCustomerRequestsTabMetrics
      ? _customerRequestsTabInProgressCount
      : _customerInProgressCount;

  int get _notificationsTabIndex => 3;

  int get _moreTabIndex => 4;

  Future<void> _showCustomerRequests({String filter = 'active'}) async {
    setState(() {
      _customerRequestFilter = filter;
      _currentIndex = 1;
    });
    if (filter == 'history' &&
        _customerAgreementCount > 0 &&
        _customerAgreements.isEmpty &&
        !_customerAgreementsLoadingMore) {
      await _loadMoreCustomerAgreements(reset: true);
      return;
    }
    if (filter != 'history') {
      await _loadCustomerRequestsTab(filter: filter, reset: true);
    }
  }

  Future<void> _setCustomerRequestFilter(String filter) async {
    if (_customerRequestFilter == filter) {
      return;
    }
    setState(() {
      _customerRequestFilter = filter;
    });
    if (filter == 'history' &&
        _customerAgreementCount > 0 &&
        _customerAgreements.isEmpty &&
        !_customerAgreementsLoadingMore) {
      await _loadMoreCustomerAgreements(reset: true);
      return;
    }
    if (filter != 'history') {
      await _loadCustomerRequestsTab(filter: filter, reset: true);
    }
  }

  Future<void> _setProviderWorkFilter(String filter) async {
    if (_providerWorkFilter == filter) {
      return;
    }
    setState(() {
      _providerWorkFilter = filter;
    });
    if (filter == 'history' &&
        _providerAgreementCount > 0 &&
        _providerAgreements.isEmpty &&
        !_providerAgreementsLoadingMore) {
      await _loadMoreProviderAgreements(reset: true);
    }
  }

  int _prefetchLimit({
    required int loadedCount,
    required bool extendedVisible,
    required int pageSize,
  }) {
    if (!extendedVisible) {
      return pageSize;
    }
    return loadedCount > pageSize ? loadedCount : pageSize;
  }

  int _agreementsPrefetchLimit({
    required int loadedCount,
    required bool historyVisible,
  }) {
    return _prefetchLimit(
      loadedCount: loadedCount,
      extendedVisible: historyVisible,
      pageSize: _agreementsPageSize,
    );
  }

  List<Map<String, dynamic>> _mergePagedItems(
    List<Map<String, dynamic>> existing,
    List<Map<String, dynamic>> next,
  ) {
    if (existing.isEmpty) {
      return next;
    }
    final merged = <Map<String, dynamic>>[...existing];
    final seenIds = existing
        .map((item) => (item['id'] ?? '').toString())
        .where((value) => value.isNotEmpty)
        .toSet();
    for (final item in next) {
      final id = (item['id'] ?? '').toString();
      if (id.isEmpty || seenIds.add(id)) {
        merged.add(item);
      }
    }
    return merged;
  }

  void _showInlineMessage(String message) {
    if (!mounted) {
      return;
    }
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(SnackBar(content: Text(message)));
  }

  Future<void> _loadCustomerRequestsTab({
    String? filter,
    bool reset = false,
    bool silent = false,
  }) async {
    final targetFilter = filter ?? _customerRequestFilter;
    if (targetFilter == 'history') {
      return;
    }
    if (_customerRequestsTabLoadingMore) {
      return;
    }
    if (!reset &&
        _customerRequestsTabFilter == targetFilter &&
        _customerRequestsTabItems.isNotEmpty &&
        _customerRequestsTabItems.length >= _customerRequestsTabCount) {
      return;
    }

    if (mounted) {
      setState(() {
        _customerRequestsTabLoadingMore = true;
        if (reset || _customerRequestsTabFilter != targetFilter) {
          _customerRequestsTabFilter = targetFilter;
          _customerRequestsTabItems = const <Map<String, dynamic>>[];
          _customerRequestsTabCount = 0;
        }
      });
    }
    try {
      final accessToken = await widget.sessionController.ensureAccessToken();
      final filteredItems = <Map<String, dynamic>>[];
      var nextOffset = 0;
      var totalCount = 0;
      do {
        final response = await widget.dataService.fetchCustomerRequests(
          accessToken: accessToken,
          scope: 'open',
          limit: _requestsPageSize,
          offset: nextOffset,
        );
        final responseItems = _mapList(response['results']);
        totalCount =
            (response['count'] as num?)?.toInt() ?? responseItems.length;
        filteredItems.addAll(responseItems);
        nextOffset += responseItems.length;
        if (responseItems.isEmpty) {
          break;
        }
      } while (nextOffset < totalCount);
      if (!mounted) {
        return;
      }
      setState(() {
        _customerRequestsTabFilter = targetFilter;
        _customerRequestsTabItems = filteredItems;
        _customerRequestsTabCount = filteredItems.length;
        _customerRequestsTabLoaded = true;
      });
    } catch (_) {
      if (!silent) {
        _showInlineMessage('Talepler şu an yüklenemedi.');
      }
    } finally {
      if (mounted) {
        setState(() {
          _customerRequestsTabLoadingMore = false;
        });
      }
    }
  }

  Future<void> _loadMoreCustomerRequests({bool reset = false}) async {
    if (_customerRequestFilter != 'history') {
      return _loadCustomerRequestsTab(
        filter: _customerRequestFilter,
        reset: reset,
      );
    }
    if (_customerRequestsLoadingMore) {
      return;
    }
    final currentItems = _customerRequests;
    if (!reset &&
        (!_customerRequestsHasMore ||
            (currentItems.isEmpty && _customerRequestCount == 0))) {
      return;
    }
    setState(() {
      _customerRequestsLoadingMore = true;
    });
    try {
      final accessToken = await widget.sessionController.ensureAccessToken();
      final response = await widget.dataService.fetchCustomerRequests(
        accessToken: accessToken,
        scope: 'open',
        limit: _requestsPageSize,
        offset: reset ? 0 : currentItems.length,
      );
      final nextItems = _mapList(response['results']);
      if (!mounted) {
        return;
      }
      setState(() {
        final updatedItems =
            reset ? nextItems : _mergePagedItems(currentItems, nextItems);
        _dashboardPayload = <String, dynamic>{
          ..._dashboardPayload,
          'results': updatedItems,
          'count': response['count'] ?? _customerRequestCount,
          'summary': response['summary'] ?? _customerSummary,
        };
        _customerRequestsVersion =
            (response['version'] ?? _customerRequestsVersion).toString();
      });
    } catch (error) {
      _showInlineMessage('Talepler şu an yüklenemedi.');
    } finally {
      if (mounted) {
        setState(() {
          _customerRequestsLoadingMore = false;
        });
      }
    }
  }

  Future<void> _loadMoreCustomerAgreements({bool reset = false}) async {
    if (_customerAgreementsLoadingMore) {
      return;
    }
    final currentItems = _customerAgreements;
    if (!reset &&
        (!_customerAgreementsHasMore ||
            currentItems.isEmpty && _customerAgreementCount == 0)) {
      return;
    }
    setState(() {
      _customerAgreementsLoadingMore = true;
    });
    try {
      final accessToken = await widget.sessionController.ensureAccessToken();
      final response = await widget.dataService.fetchCustomerRequests(
        accessToken: accessToken,
        scope: 'agreements',
        limit: _agreementsPageSize,
        offset: reset ? 0 : currentItems.length,
      );
      final nextItems = _mapList(response['results']);
      if (!mounted) {
        return;
      }
      setState(() {
        final updatedItems =
            reset ? nextItems : _mergePagedItems(currentItems, nextItems);
        _dashboardPayload = <String, dynamic>{
          ..._dashboardPayload,
          'agreements': updatedItems,
          'agreements_count': response['count'] ?? _customerAgreementCount,
        };
        _customerAgreementsVersion =
            (response['version'] ?? _customerAgreementsVersion).toString();
      });
    } catch (error) {
      _showInlineMessage('Anlaşmalar şu an yüklenemedi.');
    } finally {
      if (mounted) {
        setState(() {
          _customerAgreementsLoadingMore = false;
        });
      }
    }
  }

  Future<void> _loadMoreProviderAgreements({bool reset = false}) async {
    if (_providerAgreementsLoadingMore) {
      return;
    }
    final currentItems = _providerAgreements;
    if (!reset &&
        (!_providerAgreementsHasMore ||
            currentItems.isEmpty && _providerAgreementCount == 0)) {
      return;
    }
    setState(() {
      _providerAgreementsLoadingMore = true;
    });
    try {
      final accessToken = await widget.sessionController.ensureAccessToken();
      final response = await widget.dataService.fetchProviderAgreements(
        accessToken: accessToken,
        limit: _agreementsPageSize,
        offset: reset ? 0 : currentItems.length,
      );
      final nextItems = _mapList(response['results']);
      if (!mounted) {
        return;
      }
      setState(() {
        final updatedItems =
            reset ? nextItems : _mergePagedItems(currentItems, nextItems);
        _dashboardPayload = <String, dynamic>{
          ..._dashboardPayload,
          'agreements': updatedItems,
          'agreements_count': response['count'] ?? _providerAgreementCount,
        };
      });
    } catch (error) {
      _showInlineMessage('Anlaşmalar şu an yüklenemedi.');
    } finally {
      if (mounted) {
        setState(() {
          _providerAgreementsLoadingMore = false;
        });
      }
    }
  }

  Future<void> _loadMoreNotifications() async {
    if (_notificationsLoadingMore || !_notificationsHasMore) {
      return;
    }
    setState(() {
      _notificationsLoadingMore = true;
    });
    try {
      final accessToken = await widget.sessionController.ensureAccessToken();
      final currentResults = _mapList(_notificationsPayload['results']);
      final response = await widget.dataService.fetchNotifications(
        accessToken: accessToken,
        category: _notificationCategory,
        limit: _notificationsPageSize,
        offset: currentResults.length,
      );
      final nextResults = _mapList(response['results']);
      if (!mounted) {
        return;
      }
      setState(() {
        _notificationsPayload = <String, dynamic>{
          ..._notificationsPayload,
          ...response,
          'results': _mergePagedItems(currentResults, nextResults),
        };
        _notificationsVersion =
            (response['version'] ?? _notificationsVersion).toString();
      });
    } catch (error) {
      _showInlineMessage('Bildirimler şu an yüklenemedi.');
    } finally {
      if (mounted) {
        setState(() {
          _notificationsLoadingMore = false;
        });
      }
    }
  }

  bool _isNotFoundError(Object error) {
    return error is ApiException && error.statusCode == 404;
  }

  void _subscribeToLiveUpdates() {
    _liveUpdatesSubscription?.cancel();
    _liveUpdatesSubscription = widget.sessionController.liveUpdates.listen(
      _handleLiveUpdateEvent,
    );
  }

  void _handleLiveUpdateEvent(Map<String, dynamic> event) {
    if (!mounted ||
        _runningProviderActionKeys.isNotEmpty ||
        _appLifecycleState != AppLifecycleState.resumed ||
        !_isVisibleRoute()) {
      return;
    }
    if ((event['type'] ?? '').toString() != 'refresh.hint') {
      return;
    }

    final rawAreas = event['areas'];
    final areas = rawAreas is List
        ? rawAreas.map((item) => item.toString()).toSet()
        : const <String>{};

    if (_shouldRefreshDashboardForTab(_currentIndex) &&
        (areas.contains('dashboard') ||
            areas.contains('messages') ||
            areas.contains('request_detail'))) {
      unawaited(_loadDashboard(silent: true));
    }

    if (areas.contains('notifications') &&
        (_currentIndex == _notificationsTabIndex ||
            _notificationsPayload.isNotEmpty)) {
      unawaited(_loadNotifications(silent: true));
    }
  }

  void _startAutoRefresh() {
    _autoRefreshTimer?.cancel();
    _autoRefreshTimer = Timer.periodic(
      _refreshTickInterval,
      (_) => _refreshVisibleTabSilently(),
    );
  }

  bool _isVisibleRoute() {
    if (!mounted) {
      return false;
    }
    final route = ModalRoute.of(context);
    return route?.isCurrent ?? true;
  }

  bool _shouldRefreshDashboardForTab(int index) {
    return index < _notificationsTabIndex;
  }

  Duration _dashboardRefreshIntervalForTab(int index) {
    if (_isProvider) {
      return _providerDashboardRefreshInterval;
    }
    if (index == 0) {
      return const Duration(seconds: 10);
    }
    return _customerDashboardRefreshInterval;
  }

  bool _isRefreshDue(DateTime? lastSyncAt, {required Duration interval}) {
    if (lastSyncAt == null) {
      return true;
    }
    return DateTime.now().difference(lastSyncAt) >= interval;
  }

  String _dashboardRefreshMessage() {
    if (_isProvider) {
      return _currentIndex == 1
          ? 'Usta mesaj ve iş durumu güncellendi'
          : 'Usta paneli güncellendi';
    }
    switch (_currentIndex) {
      case 1:
        return 'Taleplerde yeni gelişme var';
      case 2:
        return 'Mesaj ve talep durumu güncellendi';
      default:
        return 'Ana ekran verileri güncellendi';
    }
  }

  void _showLiveUpdateCue({
    required String message,
    required int tabIndex,
  }) {
    if (!mounted) {
      return;
    }
    _liveUpdateTimer?.cancel();
    setState(() {
      _liveUpdateMessage = message;
      _liveUpdateTabIndex = tabIndex;
    });
    _liveUpdateTimer = Timer(const Duration(seconds: 5), () {
      if (!mounted) {
        return;
      }
      setState(() {
        _liveUpdateMessage = null;
        _liveUpdateTabIndex = null;
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
      _liveUpdateTabIndex = null;
    });
  }

  void _refreshVisibleTabSilently({bool force = false}) {
    if (!mounted ||
        _runningProviderActionKeys.isNotEmpty ||
        _appLifecycleState != AppLifecycleState.resumed ||
        !_isVisibleRoute()) {
      return;
    }

    if (_shouldRefreshDashboardForTab(_currentIndex) &&
        (force ||
            _isRefreshDue(
              _lastDashboardSyncAt,
              interval: _dashboardRefreshIntervalForTab(_currentIndex),
            ))) {
      unawaited(_loadDashboard(silent: true));
    }

    if (_currentIndex == _notificationsTabIndex &&
        (force ||
            _isRefreshDue(
              _lastNotificationSyncAt,
              interval: _notificationsRefreshInterval,
            ))) {
      unawaited(_loadNotifications(silent: true));
    }

    if (_currentIndex == _moreTabIndex &&
        _notificationPreferences.isEmpty &&
        !_preferencesLoading) {
      unawaited(_loadNotificationPreferences());
    }
  }

  Future<void> _loadDashboard({bool silent = false}) async {
    if (_dashboardRequestInFlight) {
      return;
    }
    _dashboardRequestInFlight = true;
    if (!silent) {
      _clearLiveUpdateCue();
    }
    if (!silent) {
      setState(() {
        _dashboardLoading = true;
        _dashboardError = null;
      });
    }
    try {
      final accessToken = await widget.sessionController.ensureAccessToken();
      if (_isProvider) {
        if (silent) {
          final summary =
              await widget.dataService.fetchProviderDashboardSummary(
            accessToken: accessToken,
          );
          final nextVersion = (summary['version'] ?? '').toString();
          final changed = _providerDashboardVersion.isNotEmpty &&
              nextVersion != _providerDashboardVersion;
          _providerDashboardVersion = nextVersion;
          _lastDashboardSyncAt = DateTime.now();
          if (!changed) {
            return;
          }
        }
        final payload = await widget.dataService.fetchProviderDashboard(
          accessToken: accessToken,
          agreementsLimit: _agreementsPrefetchLimit(
            loadedCount: _providerAgreements.length,
            historyVisible:
                _currentIndex == 1 && _providerWorkFilter == 'history',
          ),
        );
        final nextVersion = (payload['version'] ?? '').toString();
        final changed = _providerDashboardVersion.isNotEmpty &&
            nextVersion != _providerDashboardVersion;
        if (!mounted) {
          return;
        }
        setState(() {
          _dashboardPayload = payload;
          _dashboardError = null;
          _providerDashboardVersion = nextVersion;
        });
        if (silent && changed) {
          _showLiveUpdateCue(
            message: _dashboardRefreshMessage(),
            tabIndex: _currentIndex,
          );
        }
      } else {
        if (!silent) {
          await widget.sessionController.refreshProfile();
        }
        if (silent) {
          final summaries = await Future.wait<Map<String, dynamic>>([
            widget.dataService.fetchCustomerRequestsSummary(
              accessToken: accessToken,
              scope: 'open',
            ),
            widget.dataService.fetchCustomerRequestsSummary(
              accessToken: accessToken,
              scope: 'agreements',
            ),
          ]);
          final nextRequestsVersion =
              (summaries[0]['version'] ?? '').toString();
          final nextAgreementsVersion =
              (summaries[1]['version'] ?? '').toString();
          final changed = (_customerRequestsVersion.isNotEmpty &&
                  nextRequestsVersion != _customerRequestsVersion) ||
              (_customerAgreementsVersion.isNotEmpty &&
                  nextAgreementsVersion != _customerAgreementsVersion);
          _customerRequestsVersion = nextRequestsVersion;
          _customerAgreementsVersion = nextAgreementsVersion;
          _lastDashboardSyncAt = DateTime.now();
          if (!changed) {
            return;
          }
        }
        final requestsVisible = _currentIndex == 1 &&
            !_isProvider &&
            _customerRequestFilter != 'history';
        final requestLimit = _prefetchLimit(
          loadedCount: _customerRequests.length,
          extendedVisible: requestsVisible,
          pageSize: _requestsPageSize,
        );
        final responses = await Future.wait<Map<String, dynamic>>([
          widget.dataService.fetchCustomerRequests(
            accessToken: accessToken,
            limit: requestLimit,
            offset: 0,
            scope: 'open',
          ),
          widget.dataService.fetchCustomerRequests(
            accessToken: accessToken,
            limit: _agreementsPrefetchLimit(
              loadedCount: _customerAgreements.length,
              historyVisible:
                  _currentIndex == 1 && _customerRequestFilter == 'history',
            ),
            offset: 0,
            scope: 'agreements',
          ),
        ]);
        final requestsPayload = responses[0];
        final agreementsPayload = responses[1];
        final payload = <String, dynamic>{
          ...requestsPayload,
          'agreements': agreementsPayload['results'] ?? const [],
          'agreements_count': agreementsPayload['count'] ?? 0,
        };
        final nextRequestsVersion =
            (requestsPayload['version'] ?? '').toString();
        final nextAgreementsVersion =
            (agreementsPayload['version'] ?? '').toString();
        final changed = (_customerRequestsVersion.isNotEmpty &&
                nextRequestsVersion != _customerRequestsVersion) ||
            (_customerAgreementsVersion.isNotEmpty &&
                nextAgreementsVersion != _customerAgreementsVersion);
        if (!mounted) {
          return;
        }
        setState(() {
          _dashboardPayload = payload;
          _dashboardError = null;
          _customerRequestsVersion = nextRequestsVersion;
          _customerAgreementsVersion = nextAgreementsVersion;
        });
        final requestsTabFilter =
            _currentIndex == 1 ? _customerRequestFilter : 'active';
        if (requestsTabFilter != 'history') {
          await _loadCustomerRequestsTab(
            filter: requestsTabFilter,
            reset: true,
            silent: silent,
          );
        }
        if (silent && changed) {
          _showLiveUpdateCue(
            message: _dashboardRefreshMessage(),
            tabIndex: _currentIndex,
          );
        }
      }
      _lastDashboardSyncAt = DateTime.now();
    } catch (error) {
      if (!mounted || silent) {
        return;
      }
      setState(() {
        _dashboardError = error.toString();
      });
    } finally {
      _dashboardRequestInFlight = false;
      if (mounted && !silent) {
        setState(() {
          _dashboardLoading = false;
        });
      }
    }
  }

  Future<void> _loadNotifications({
    String? category,
    bool silent = false,
  }) async {
    if (_notificationsRequestInFlight) {
      return;
    }
    _notificationsRequestInFlight = true;
    if (!silent) {
      _clearLiveUpdateCue();
    }
    final nextCategory = category ?? _notificationCategory;
    final categoryChanged = nextCategory != _notificationCategory;
    if (!silent) {
      setState(() {
        _notificationsLoading = true;
        _notificationsError = null;
        _notificationCategory = nextCategory;
      });
    } else if (nextCategory != _notificationCategory && mounted) {
      setState(() {
        _notificationCategory = nextCategory;
      });
    }
    try {
      final accessToken = await widget.sessionController.ensureAccessToken();
      final preserveVisibleNotifications =
          !categoryChanged && _currentIndex == _notificationsTabIndex;
      final notificationLimit = _prefetchLimit(
        loadedCount: _mapList(_notificationsPayload['results']).length,
        extendedVisible: preserveVisibleNotifications,
        pageSize: _notificationsPageSize,
      );
      if (silent) {
        final summary = await widget.dataService.fetchNotificationsSummary(
          accessToken: accessToken,
          category: nextCategory,
        );
        final nextVersion = (summary['version'] ?? '').toString();
        final changed = _notificationsVersion.isNotEmpty &&
            nextVersion != _notificationsVersion;
        _notificationsVersion = nextVersion;
        _lastNotificationSyncAt = DateTime.now();
        if (!changed) {
          return;
        }
      }
      final payload = await widget.dataService.fetchNotifications(
        accessToken: accessToken,
        category: nextCategory,
        limit: notificationLimit,
        offset: 0,
      );
      final nextVersion = (payload['version'] ?? '').toString();
      final changed = _notificationsVersion.isNotEmpty &&
          nextVersion != _notificationsVersion;
      if (!mounted) {
        return;
      }
      setState(() {
        _notificationsPayload = payload;
        _notificationsFallbackToWeb = false;
        _notificationsError = null;
        _notificationsVersion = nextVersion;
      });
      if (silent && changed) {
        _showLiveUpdateCue(
          message: 'Yeni bildirimler alındı',
          tabIndex: _notificationsTabIndex,
        );
      }
      _lastNotificationSyncAt = DateTime.now();
    } catch (error) {
      if (_isNotFoundError(error)) {
        if (!mounted) {
          return;
        }
        setState(() {
          _notificationsFallbackToWeb = true;
          _notificationsPayload = const {};
        });
        return;
      }
      if (!mounted || silent) {
        return;
      }
      setState(() {
        _notificationsError = error.toString();
      });
    } finally {
      _notificationsRequestInFlight = false;
      if (mounted && !silent) {
        setState(() {
          _notificationsLoading = false;
        });
      }
    }
  }

  Future<void> _loadNotificationPreferences() async {
    setState(() {
      _preferencesLoading = true;
      _preferencesError = null;
    });
    try {
      final accessToken = await widget.sessionController.ensureAccessToken();
      final payload = await widget.dataService
          .fetchNotificationPreferences(accessToken: accessToken);
      if (!mounted) {
        return;
      }
      setState(() {
        _notificationPreferences = payload;
        _notificationPreferencesFallbackToWeb = false;
      });
    } catch (error) {
      if (_isNotFoundError(error)) {
        if (!mounted) {
          return;
        }
        setState(() {
          _notificationPreferencesFallbackToWeb = true;
          _notificationPreferences = const {};
        });
        return;
      }
      if (!mounted) {
        return;
      }
      setState(() {
        _preferencesError = error.toString();
      });
    } finally {
      if (mounted) {
        setState(() {
          _preferencesLoading = false;
        });
      }
    }
  }

  Future<void> _updateNotificationPreference({
    required String key,
    required bool value,
  }) async {
    final previous = Map<String, dynamic>.from(_notificationPreferences);
    final next = Map<String, dynamic>.from(_notificationPreferences)
      ..[key] = value;
    setState(() {
      _notificationPreferences = next;
      _preferencesSaving = true;
      _preferencesError = null;
    });
    try {
      final accessToken = await widget.sessionController.ensureAccessToken();
      final payload = await widget.dataService.updateNotificationPreferences(
        accessToken: accessToken,
        allowMessageNotifications: next['allow_message_notifications'] == true,
        allowRequestNotifications: next['allow_request_notifications'] == true,
        allowAppointmentNotifications:
            next['allow_appointment_notifications'] == true,
      );
      if (!mounted) {
        return;
      }
      setState(() {
        _notificationPreferences = payload;
      });
      if (_notificationsPayload.isNotEmpty) {
        await _loadNotifications();
      }
    } catch (error) {
      if (!mounted) {
        return;
      }
      setState(() {
        _notificationPreferences = previous;
        _preferencesError = error.toString();
      });
    } finally {
      if (mounted) {
        setState(() {
          _preferencesSaving = false;
        });
      }
    }
  }

  Future<void> _markNotificationRead(String entryId) async {
    try {
      final accessToken = await widget.sessionController.ensureAccessToken();
      final payload = await widget.dataService.markNotificationRead(
        accessToken: accessToken,
        entryId: entryId,
      );
      final results = _mapList(_notificationsPayload['results'])
        ..removeWhere((item) => item['entry_id'] == entryId);
      if (!mounted) {
        return;
      }
      setState(() {
        final previousCount =
            (_notificationsPayload['count'] as num?)?.toInt() ?? results.length;
        _notificationsPayload = {
          ..._notificationsPayload,
          'results': results,
          'count': previousCount > 0 ? previousCount - 1 : 0,
          'unread_count':
              payload['unread_notifications_count'] ?? results.length,
        };
      });
    } catch (_) {
      // Keep navigation working even if the local list cannot be updated.
    }
  }

  Future<void> _markAllNotificationsRead() async {
    setState(() {
      _notificationsLoading = true;
      _notificationsError = null;
    });
    try {
      final accessToken = await widget.sessionController.ensureAccessToken();
      await widget.dataService
          .markAllNotificationsRead(accessToken: accessToken);
      if (!mounted) {
        return;
      }
      setState(() {
        _notificationsPayload = const {
          'count': 0,
          'unread_count': 0,
          'results': <Map<String, dynamic>>[],
        };
      });
    } catch (error) {
      if (!mounted) {
        return;
      }
      setState(() {
        _notificationsError = error.toString();
      });
    } finally {
      if (mounted) {
        setState(() {
          _notificationsLoading = false;
        });
      }
    }
  }

  Future<void> _openThread({
    required int requestId,
    required String title,
    required String subtitle,
  }) async {
    await Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (_) => RequestThreadScreen(
          sessionController: widget.sessionController,
          dataService: widget.dataService,
          requestId: requestId,
          title: title,
          subtitle: subtitle,
        ),
      ),
    );
    await _loadDashboard();
    if (_notificationsPayload.isNotEmpty) {
      await _loadNotifications();
    }
  }

  Future<void> _openProviderCatalog() async {
    await Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (_) => ProviderCatalogScreen(
          sessionController: widget.sessionController,
          dataService: widget.dataService,
        ),
      ),
    );
    await _loadDashboard();
    if (_notificationsPayload.isNotEmpty) {
      await _loadNotifications();
    }
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
    if (created == true) {
      await _loadDashboard(silent: true);
      if (_notificationsPayload.isNotEmpty) {
        await _loadNotifications(silent: true);
      }
    }
  }

  Future<void> _openRequestDetail(int requestId) async {
    final changed = await Navigator.of(context).push<bool>(
      MaterialPageRoute<bool>(
        builder: (_) => RequestDetailScreen(
          sessionController: widget.sessionController,
          dataService: widget.dataService,
          requestId: requestId,
        ),
      ),
    );
    if (changed == true) {
      await _loadDashboard(silent: true);
      if (_notificationsPayload.isNotEmpty) {
        await _loadNotifications(silent: true);
      }
    }
  }

  Future<void> _openNotification(Map<String, dynamic> item) async {
    final entryId = (item['entry_id'] ?? '').toString();
    if (entryId.isNotEmpty) {
      await _markNotificationRead(entryId);
    }
    final serviceRequestId = (item['service_request_id'] as num?)?.toInt() ?? 0;
    final kind = (item['kind'] ?? '').toString();
    if (kind == 'message' && serviceRequestId > 0) {
      await _openThread(
        requestId: serviceRequestId,
        title: 'Talep #$serviceRequestId',
        subtitle: (item['counterparty_line'] ?? 'Mesajlaşma').toString(),
      );
      return;
    }

    if (serviceRequestId > 0) {
      await _openRequestDetail(serviceRequestId);
      return;
    }

    final link = (item['link'] ?? '').toString();
    if (link.isNotEmpty) {
      await _openSiteFallback(
        _normalizeRelativeSitePath(link),
        pageTitle: 'UstaBul',
      );
      return;
    }
    if (!mounted) {
      return;
    }
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
          content: Text('Bu bildirim için açılacak bir ekran bulunamadı.')),
    );
  }

  Future<void> _openSiteFallback(String path, {String? pageTitle}) async {
    final ready = await widget.sessionController.ensureWebSession();
    if (!ready) {
      if (!mounted) {
        return;
      }
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text(
            'Site görünümü için tekrar giriş yapmanız gerekebilir.',
          ),
        ),
      );
    }
    if (!mounted) {
      return;
    }
    await Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (_) => SiteShellScreen.relativePath(
          path,
          pageTitle: pageTitle,
        ),
      ),
    );
    await _loadDashboard();
    if (_notificationsPayload.isNotEmpty) {
      await _loadNotifications();
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
        const SnackBar(content: Text('Cihazda ilgili uygulama açılamadı.')),
      );
    }
  }

  void _handleTabChange(int index) {
    setState(() {
      _currentIndex = index;
    });
    if (!_isProvider && index == 1) {
      if (_customerRequestFilter == 'history') {
        if (_customerAgreementCount > 0 &&
            _customerAgreements.isEmpty &&
            !_customerAgreementsLoadingMore) {
          _loadMoreCustomerAgreements(reset: true);
        }
      } else if (_customerRequestsTabFilter != _customerRequestFilter ||
          _customerRequestsTabItems.isEmpty) {
        _loadCustomerRequestsTab(filter: _customerRequestFilter, reset: true);
      }
    }
    if (index == _notificationsTabIndex &&
        _notificationsPayload.isEmpty &&
        !_notificationsLoading) {
      _loadNotifications();
      return;
    }
    if (index == _moreTabIndex &&
        _notificationPreferences.isEmpty &&
        !_preferencesLoading) {
      _loadNotificationPreferences();
      return;
    }
    if (_shouldRefreshDashboardForTab(index)) {
      _refreshVisibleTabSilently(force: true);
    }
  }

  Future<void> _setThemePreference(AppThemePreference preference) async {
    await widget.themeController.setPreference(preference);
  }

  bool _isProviderActionBusy(String key) {
    return _runningProviderActionKeys.contains(key);
  }

  void _applyDashboardSnapshot(dynamic rawSnapshot) {
    if (rawSnapshot is! Map) {
      return;
    }
    final snapshot = rawSnapshot.map<String, dynamic>(
      (key, value) => MapEntry(key.toString(), value),
    );
    if (!mounted) {
      return;
    }
    setState(() {
      _dashboardPayload = <String, dynamic>{
        ..._dashboardPayload,
        'snapshot': snapshot,
      };
      _dashboardError = null;
    });
  }

  Future<void> _runProviderAction({
    required String actionKey,
    required Future<Map<String, dynamic>> Function(String accessToken) action,
  }) async {
    if (_runningProviderActionKeys.contains(actionKey)) {
      return;
    }
    setState(() {
      _runningProviderActionKeys.add(actionKey);
    });
    try {
      final accessToken = await widget.sessionController.ensureAccessToken();
      final payload = await action(accessToken);
      if (!mounted) {
        return;
      }
      final message = (payload['message'] ?? 'İşlem tamamlandı.').toString();
      ScaffoldMessenger.of(context)
        ..hideCurrentSnackBar()
        ..showSnackBar(SnackBar(content: Text(message)));
      _applyDashboardSnapshot(payload['snapshot']);
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (!mounted) {
          return;
        }
        unawaited(_loadDashboard(silent: true));
        if (_notificationsPayload.isNotEmpty) {
          unawaited(_loadNotifications(silent: true));
        }
      });
    } catch (error) {
      if (!mounted) {
        return;
      }
      final message = error is ApiException && error.statusCode == 404
          ? 'Bu usta işlemi canlı backend tarafında henüz yayınlanmamış. Web görünümüne yönlendirmeyi kapattım.'
          : error.toString();
      ScaffoldMessenger.of(context)
        ..hideCurrentSnackBar()
        ..showSnackBar(SnackBar(content: Text(message)));
    } finally {
      if (mounted) {
        setState(() {
          _runningProviderActionKeys.remove(actionKey);
        });
      }
    }
  }

  Future<String?> _promptForProviderNote({
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
          maxLength: 100,
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

  Future<bool> _confirmProviderAction({
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

  Future<void> _waitForUiToSettle() async {
    await Future<void>.delayed(Duration.zero);
    await WidgetsBinding.instance.endOfFrame;
  }

  Future<void> _acceptProviderOfferFromDashboard(
    Map<String, dynamic> item,
  ) async {
    final offerId = (item['id'] as num?)?.toInt();
    if (offerId == null || offerId <= 0) {
      return;
    }
    final note = await _promptForProviderNote(
      title: 'Teklifi onayla',
      hintText: 'Kısa not (opsiyonel)',
    );
    if (note == null) {
      return;
    }
    await _waitForUiToSettle();
    if (!mounted) {
      return;
    }
    await _runProviderAction(
      actionKey: 'offer:$offerId:accept',
      action: (accessToken) => widget.dataService.acceptProviderOffer(
        accessToken: accessToken,
        offerId: offerId,
        quoteNote: note,
      ),
    );
  }

  Future<void> _rejectProviderOfferFromDashboard(
    Map<String, dynamic> item,
  ) async {
    final offerId = (item['id'] as num?)?.toInt();
    if (offerId == null || offerId <= 0) {
      return;
    }
    final confirmed = await _confirmProviderAction(
      title: 'Teklifi reddet',
      message: 'Bu teklifi reddetmek istiyor musunuz?',
    );
    if (!confirmed) {
      return;
    }
    await _waitForUiToSettle();
    if (!mounted) {
      return;
    }
    await _runProviderAction(
      actionKey: 'offer:$offerId:reject',
      action: (accessToken) => widget.dataService.rejectProviderOffer(
        accessToken: accessToken,
        offerId: offerId,
      ),
    );
  }

  Future<void> _withdrawProviderOfferFromDashboard(
    Map<String, dynamic> item,
  ) async {
    final offerId = (item['id'] as num?)?.toInt();
    if (offerId == null || offerId <= 0) {
      return;
    }
    final confirmed = await _confirmProviderAction(
      title: 'Teklifi geri çek',
      message: 'Bu teklifi geri çekmek istiyor musunuz?',
    );
    if (!confirmed) {
      return;
    }
    await _waitForUiToSettle();
    if (!mounted) {
      return;
    }
    await _runProviderAction(
      actionKey: 'offer:$offerId:withdraw',
      action: (accessToken) => widget.dataService.withdrawProviderOffer(
        accessToken: accessToken,
        offerId: offerId,
      ),
    );
  }

  Future<void> _confirmProviderAppointmentFromDashboard(
    Map<String, dynamic> item,
  ) async {
    final appointmentId = (item['id'] as num?)?.toInt();
    if (appointmentId == null || appointmentId <= 0) {
      return;
    }
    final note = await _promptForProviderNote(
      title: 'Randevuyu onayla',
      hintText: 'Kısa not (opsiyonel)',
    );
    if (note == null) {
      return;
    }
    await _waitForUiToSettle();
    if (!mounted) {
      return;
    }
    await _runProviderAction(
      actionKey: 'appointment:$appointmentId:confirm',
      action: (accessToken) => widget.dataService.confirmProviderAppointment(
        accessToken: accessToken,
        appointmentId: appointmentId,
        providerNote: note,
      ),
    );
  }

  Future<void> _rejectProviderAppointmentFromDashboard(
    Map<String, dynamic> item,
  ) async {
    final appointmentId = (item['id'] as num?)?.toInt();
    if (appointmentId == null || appointmentId <= 0) {
      return;
    }
    final note = await _promptForProviderNote(
      title: 'Randevuyu reddet',
      hintText: 'Kısa not (opsiyonel)',
    );
    if (note == null) {
      return;
    }
    await _waitForUiToSettle();
    if (!mounted) {
      return;
    }
    await _runProviderAction(
      actionKey: 'appointment:$appointmentId:reject',
      action: (accessToken) => widget.dataService.rejectProviderAppointment(
        accessToken: accessToken,
        appointmentId: appointmentId,
        providerNote: note,
      ),
    );
  }

  Future<void> _completeProviderAppointmentFromDashboard(
    Map<String, dynamic> item,
  ) async {
    final appointmentId = (item['id'] as num?)?.toInt();
    if (appointmentId == null || appointmentId <= 0) {
      return;
    }
    final confirmed = await _confirmProviderAction(
      title: 'İşi bitir',
      message: 'Bu işi tamamlandı olarak işaretlemek istiyor musunuz?',
    );
    if (!confirmed) {
      return;
    }
    await _waitForUiToSettle();
    if (!mounted) {
      return;
    }
    await _runProviderAction(
      actionKey: 'appointment:$appointmentId:complete',
      action: (accessToken) => widget.dataService.completeProviderAppointment(
        accessToken: accessToken,
        appointmentId: appointmentId,
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
            (item) => item.map((key, value) => MapEntry(key.toString(), value)))
        .toList();
  }

  String _normalizeRelativeSitePath(String link) {
    final parsed = Uri.tryParse(link);
    if (parsed == null) {
      return '/';
    }
    if (!parsed.hasScheme) {
      return parsed.toString();
    }
    final buffer = StringBuffer(parsed.path.isEmpty ? '/' : parsed.path);
    if (parsed.hasQuery) {
      buffer.write('?${parsed.query}');
    }
    if (parsed.hasFragment) {
      buffer.write('#${parsed.fragment}');
    }
    return buffer.toString();
  }

  Widget _buildLiveUpdateBanner() {
    if (_liveUpdateMessage == null || _liveUpdateTabIndex != _currentIndex) {
      return const SizedBox.shrink();
    }
    return Container(
      width: double.infinity,
      margin: const EdgeInsets.fromLTRB(16, 12, 16, 0),
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
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
    );
  }

  @override
  Widget build(BuildContext context) {
    final session = widget.sessionController.session;
    if (session == null) {
      return const SizedBox.shrink();
    }

    final _ = <String>[
      _isProvider ? 'UstaBul Usta' : 'UstaBul Müşteri',
      'Mesajlar',
      'Bildirimler',
      'Daha Fazla',
    ];

    final screenTitles = _isProvider
        ? const <String>[
            'Usta paneli',
            'İşlerim',
            'Mesajlar',
            'Bildirimler',
            'Daha Fazla',
          ]
        : const <String>[
            'Ana Sayfa',
            'Taleplerim',
            'Mesajlar',
            'Bildirimler',
            'Daha Fazla',
          ];

    return Scaffold(
      appBar: AppBar(
        title: Text(screenTitles[_currentIndex]),
        actions: [
          if (_shouldRefreshDashboardForTab(_currentIndex))
            IconButton(
              onPressed: _dashboardLoading ? null : _loadDashboard,
              icon: const Icon(Icons.refresh_rounded),
              tooltip: 'Yenile',
            ),
          if (_currentIndex == _notificationsTabIndex)
            IconButton(
              onPressed: _notificationsLoading ? null : _loadNotifications,
              icon: const Icon(Icons.refresh_rounded),
              tooltip: 'Yenile',
            ),
        ],
      ),
      body: BrandBackdrop(
        child: Column(
          children: [
            _buildLiveUpdateBanner(),
            Expanded(
              child: AnimatedSwitcher(
                duration: const Duration(milliseconds: 220),
                child: switch (_currentIndex) {
                  0 => _DashboardTab(
                      key: const ValueKey('dashboard'),
                      isProvider: _isProvider,
                      loading: _dashboardLoading,
                      error: _dashboardError,
                      sessionSnapshot: _sessionSnapshot,
                      dashboardPayload: _dashboardPayload,
                      customerRequests: _customerDashboardRequests,
                      customerRequestCount: _customerDashboardRequestCount,
                      customerActiveCount: _customerDashboardActiveCount,
                      customerDecisionCount: _customerDashboardDecisionCount,
                      customerInProgressCount:
                          _customerDashboardInProgressCount,
                      customerWaitingCount: _customerWaitingCount,
                      customerAgreementCount: _customerAgreementCount,
                      providerPendingOffers: _providerPendingOffers,
                      providerWaitingSelection: _providerWaitingSelection,
                      providerActiveThreads: _providerActiveThreads,
                      providerPendingAppointments: _providerPendingAppointments,
                      onRefresh: _loadDashboard,
                      onOpenThread: _openThread,
                      onOpenRequestDetail: _openRequestDetail,
                      onOpenRequestsTab: _showCustomerRequests,
                      onOpenProviderCatalog: _openProviderCatalog,
                      onCreateRequest: _openRequestCreate,
                      onOpenWebPanel: null,
                      isProviderActionBusy: _isProviderActionBusy,
                      onAcceptProviderOffer: _acceptProviderOfferFromDashboard,
                      onRejectProviderOffer: _rejectProviderOfferFromDashboard,
                      onWithdrawProviderOffer:
                          _withdrawProviderOfferFromDashboard,
                      onConfirmProviderAppointment:
                          _confirmProviderAppointmentFromDashboard,
                      onRejectProviderAppointment:
                          _rejectProviderAppointmentFromDashboard,
                      onCompleteProviderAppointment:
                          _completeProviderAppointmentFromDashboard,
                    ),
                  1 => _isProvider
                      ? _ProviderWorkTab(
                          key: const ValueKey('provider-work'),
                          loading: _dashboardLoading,
                          error: _dashboardError,
                          selectedFilter: _providerWorkFilter,
                          summary: _providerSummary,
                          providerPendingOffers: _providerPendingOffers,
                          providerWaitingSelection: _providerWaitingSelection,
                          providerActiveThreads: _providerActiveThreads,
                          providerPendingAppointments:
                              _providerPendingAppointments,
                          providerAgreements: _providerAgreements,
                          agreementsLoadingMore: _providerAgreementsLoadingMore,
                          hasMoreAgreements: _providerAgreementsHasMore,
                          onRefresh: _loadDashboard,
                          onFilterChanged: _setProviderWorkFilter,
                          onLoadMoreAgreements: () =>
                              _loadMoreProviderAgreements(),
                          onOpenThread: _openThread,
                          onOpenRequestDetail: _openRequestDetail,
                          isProviderActionBusy: _isProviderActionBusy,
                          onAcceptProviderOffer:
                              _acceptProviderOfferFromDashboard,
                          onRejectProviderOffer:
                              _rejectProviderOfferFromDashboard,
                          onWithdrawProviderOffer:
                              _withdrawProviderOfferFromDashboard,
                          onConfirmProviderAppointment:
                              _confirmProviderAppointmentFromDashboard,
                          onRejectProviderAppointment:
                              _rejectProviderAppointmentFromDashboard,
                          onCompleteProviderAppointment:
                              _completeProviderAppointmentFromDashboard,
                        )
                      : _RequestsTab(
                          key: const ValueKey('requests'),
                          loading: _dashboardLoading ||
                              (_customerRequestFilter != 'history' &&
                                  _customerRequestsTabLoadingMore &&
                                  _customerRequestsTabItems.isEmpty),
                          error: _dashboardError,
                          selectedFilter: _customerRequestFilter,
                          customerRequests: _customerVisibleRequests,
                          customerRequestCount:
                              _customerRequestFilter == 'history'
                                  ? _customerAgreementCount
                                  : _customerVisibleRequests.length,
                          customerActiveCount: _customerRequestsTabActiveCount,
                          customerDecisionCount:
                              _customerRequestsTabDecisionCount,
                          customerInProgressCount:
                              _customerRequestsTabInProgressCount,
                          customerAgreementCount: _customerAgreementCount,
                          visibleRequests: _customerVisibleRequests,
                          requestsLoadingMore: _customerRequestsTabLoadingMore,
                          hasMoreRequests: false,
                          agreementsLoadingMore: _customerAgreementsLoadingMore,
                          hasMoreAgreements: _customerAgreementsHasMore,
                          onRefresh: _loadDashboard,
                          onFilterChanged: _setCustomerRequestFilter,
                          onLoadMoreRequests: () => _loadMoreCustomerRequests(),
                          onLoadMoreAgreements: () =>
                              _loadMoreCustomerAgreements(),
                          onOpenRequestDetail: _openRequestDetail,
                          onOpenProviderCatalog: _openProviderCatalog,
                          onCreateRequest: _openRequestCreate,
                        ),
                  2 => _MessagesTab(
                      key: const ValueKey('messages'),
                      isProvider: _isProvider,
                      loading: _dashboardLoading,
                      error: _dashboardError,
                      threads: _messageThreads,
                      onRefresh: _loadDashboard,
                      onOpenThread: _openThread,
                    ),
                  3 => _NotificationsTab(
                      key: const ValueKey('notifications'),
                      loading: _notificationsLoading,
                      error: _notificationsError,
                      payload: _notificationsPayload,
                      category: _notificationCategory,
                      fallbackToWeb: _notificationsFallbackToWeb,
                      loadingMore: _notificationsLoadingMore,
                      hasMore: _notificationsHasMore,
                      onRefresh: _loadNotifications,
                      onCategoryChanged: (value) =>
                          _loadNotifications(category: value),
                      onLoadMore: _loadMoreNotifications,
                      onOpenNotification: _openNotification,
                      onMarkAllRead: _markAllNotificationsRead,
                      onOpenWebNotifications: () => _openSiteFallback(
                        '/bildirimler/',
                        pageTitle: 'Bildirimler',
                      ),
                    ),
                  _ => _MoreTab(
                      key: const ValueKey('more'),
                      sessionController: widget.sessionController,
                      themePreference: widget.themeController.preference,
                      loading: _preferencesLoading,
                      saving: _preferencesSaving,
                      error: _preferencesError,
                      notificationPreferences: _notificationPreferences,
                      preferencesFallbackToWeb:
                          _notificationPreferencesFallbackToWeb,
                      onThemeChanged: _setThemePreference,
                      onRetry: _loadNotificationPreferences,
                      onTogglePreference: _updateNotificationPreference,
                      onOpenFallback: _openSiteFallback,
                      onLaunchExternal: _launchExternal,
                    ),
                },
              ),
            ),
          ],
        ),
      ),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _currentIndex,
        onDestinationSelected: _handleTabChange,
        destinations: _isProvider
            ? const [
                NavigationDestination(
                  icon: Icon(Icons.dashboard_outlined),
                  selectedIcon: Icon(Icons.dashboard_rounded),
                  label: 'Ana Ekran',
                ),
                NavigationDestination(
                  icon: Icon(Icons.work_outline_rounded),
                  selectedIcon: Icon(Icons.work_rounded),
                  label: 'İşlerim',
                ),
                NavigationDestination(
                  icon: Icon(Icons.forum_outlined),
                  selectedIcon: Icon(Icons.forum_rounded),
                  label: 'Mesajlar',
                ),
                NavigationDestination(
                  icon: Icon(Icons.notifications_none_rounded),
                  selectedIcon: Icon(Icons.notifications_rounded),
                  label: 'Bildirimler',
                ),
                NavigationDestination(
                  icon: Icon(Icons.tune_outlined),
                  selectedIcon: Icon(Icons.tune_rounded),
                  label: 'Daha Fazla',
                ),
              ]
            : const [
                NavigationDestination(
                  icon: Icon(Icons.dashboard_outlined),
                  selectedIcon: Icon(Icons.dashboard_rounded),
                  label: 'Ana Sayfa',
                ),
                NavigationDestination(
                  icon: Icon(Icons.receipt_long_outlined),
                  selectedIcon: Icon(Icons.receipt_long_rounded),
                  label: 'Taleplerim',
                ),
                NavigationDestination(
                  icon: Icon(Icons.forum_outlined),
                  selectedIcon: Icon(Icons.forum_rounded),
                  label: 'Mesajlar',
                ),
                NavigationDestination(
                  icon: Icon(Icons.notifications_none_rounded),
                  selectedIcon: Icon(Icons.notifications_rounded),
                  label: 'Bildirimler',
                ),
                NavigationDestination(
                  icon: Icon(Icons.tune_outlined),
                  selectedIcon: Icon(Icons.tune_rounded),
                  label: 'Daha Fazla',
                ),
              ],
      ),
    );
  }
}

class _DashboardTab extends StatelessWidget {
  const _DashboardTab({
    super.key,
    required this.isProvider,
    required this.loading,
    required this.error,
    required this.sessionSnapshot,
    required this.dashboardPayload,
    required this.customerRequests,
    required this.customerRequestCount,
    required this.customerActiveCount,
    required this.customerDecisionCount,
    required this.customerInProgressCount,
    required this.customerWaitingCount,
    required this.customerAgreementCount,
    required this.providerPendingOffers,
    required this.providerWaitingSelection,
    required this.providerActiveThreads,
    required this.providerPendingAppointments,
    required this.onRefresh,
    required this.onOpenThread,
    required this.onOpenRequestDetail,
    required this.onOpenRequestsTab,
    required this.isProviderActionBusy,
    required this.onAcceptProviderOffer,
    required this.onRejectProviderOffer,
    required this.onWithdrawProviderOffer,
    required this.onConfirmProviderAppointment,
    required this.onRejectProviderAppointment,
    required this.onCompleteProviderAppointment,
    required this.onOpenProviderCatalog,
    required this.onCreateRequest,
    this.onOpenWebPanel,
  });

  final bool isProvider;
  final bool loading;
  final String? error;
  final Map<String, dynamic> sessionSnapshot;
  final Map<String, dynamic> dashboardPayload;
  final List<Map<String, dynamic>> customerRequests;
  final int customerRequestCount;
  final int customerActiveCount;
  final int customerDecisionCount;
  final int customerInProgressCount;
  final int customerWaitingCount;
  final int customerAgreementCount;
  final List<Map<String, dynamic>> providerPendingOffers;
  final List<Map<String, dynamic>> providerWaitingSelection;
  final List<Map<String, dynamic>> providerActiveThreads;
  final List<Map<String, dynamic>> providerPendingAppointments;
  final Future<void> Function() onRefresh;
  final Future<void> Function({
    required int requestId,
    required String title,
    required String subtitle,
  }) onOpenThread;
  final Future<void> Function(int requestId) onOpenRequestDetail;
  final Future<void> Function({String filter}) onOpenRequestsTab;
  final bool Function(String key) isProviderActionBusy;
  final Future<void> Function(Map<String, dynamic> item) onAcceptProviderOffer;
  final Future<void> Function(Map<String, dynamic> item) onRejectProviderOffer;
  final Future<void> Function(Map<String, dynamic> item)
      onWithdrawProviderOffer;
  final Future<void> Function(Map<String, dynamic> item)
      onConfirmProviderAppointment;
  final Future<void> Function(Map<String, dynamic> item)
      onRejectProviderAppointment;
  final Future<void> Function(Map<String, dynamic> item)
      onCompleteProviderAppointment;
  final Future<void> Function() onOpenProviderCatalog;
  final Future<void> Function({
    int? preferredProviderId,
    String? preferredProviderName,
  }) onCreateRequest;
  final Future<void> Function()? onOpenWebPanel;

  @override
  Widget build(BuildContext context) {
    if (loading) {
      return const Center(child: CircularProgressIndicator());
    }
    if (error != null) {
      return _ErrorState(message: error!, onRetry: onRefresh);
    }

    return RefreshIndicator(
      onRefresh: onRefresh,
      child: ListView(
        padding: const EdgeInsets.fromLTRB(16, 12, 16, 24),
        children: isProvider
            ? _buildProviderContent(context)
            : _buildCustomerContent(context),
      ),
    );
  }

  List<Widget> _buildCustomerContent(BuildContext context) {
    final totalActiveCount = customerActiveCount;
    final matchedCount = customerInProgressCount;
    final pendingCustomerCount = customerDecisionCount;
    final waitingProviderCount = customerWaitingCount;
    final historyCount = customerAgreementCount;
    final recentRequests = customerRequests
        .where((item) => _matchesCustomerRequestFilter(item, 'active'))
        .take(3)
        .toList();
    final previewActiveCount = recentRequests.length;
    final useModernLayout = Theme.of(context).useMaterial3;

    if (useModernLayout) {
      return [
        const _SectionHero(
          title: 'Müşteri paneli',
          subtitle:
              'Web sitesindeki akışa yakın şekilde, ama daha sade bir mobil düzenle ilerleyin.',
        ),
        const SizedBox(height: 16),
        Row(
          children: [
            Expanded(
              child: _QuickActionCard(
                icon: Icons.search_rounded,
                title: 'Usta bul',
                subtitle: 'Filtrele, karşılaştır ve uygun ustayı seç.',
                onTap: onOpenProviderCatalog,
              ),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: _QuickActionCard(
                icon: Icons.add_circle_outline_rounded,
                title: 'Talep oluştur',
                subtitle: 'Yeni iş talebini uygulamadan hızlıca gönder.',
                onTap: () => onCreateRequest(),
              ),
            ),
          ],
        ),
        const SizedBox(height: 16),
        Row(
          children: [
            Expanded(
              child: _MetricCard(
                label: 'Son aktif talepler',
                value: '$previewActiveCount',
                tone: 'primary',
              ),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: _MetricCard(
                label: 'Karar bekleyen',
                value: '$pendingCustomerCount',
                tone: 'warning',
              ),
            ),
          ],
        ),
        const SizedBox(height: 10),
        Row(
          children: [
            Expanded(
              child: _MetricCard(
                label: 'İş sürüyor',
                value: '$matchedCount',
                tone: 'success',
              ),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: _MetricCard(
                label: 'Anlaşmalar',
                value: '$historyCount',
                tone: 'primary',
              ),
            ),
          ],
        ),
        const SizedBox(height: 24),
        const _SectionTitle(
          title: 'Öncelikli alanlar',
          subtitle:
              'Ana ekran özet kalsın, detaylı takip ise ayrı Taleplerim sekmesine taşınsın.',
        ),
        Row(
          children: [
            Expanded(
              child: _SpotlightCard(
                icon: Icons.receipt_long_rounded,
                title: 'Taleplerim',
                body:
                    'Sadece aktif talepler burada kalır; iş kapanınca listeden düşer.',
                actionLabel: 'Sekmeyi aç',
                onTap: () => onOpenRequestsTab(),
              ),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: _SpotlightCard(
                icon: Icons.history_rounded,
                title: 'Anlaşmalar',
                body: historyCount > 0
                    ? '$historyCount anlaşma kaydın webdeki Anlaşmalar ekranına benzer şekilde hazır.'
                    : 'Eşleşen, tamamlanan ve iptal edilen anlaşmalar burada toplanır.',
                actionLabel: 'Görüntüle',
                onTap: () => onOpenRequestsTab(filter: 'history'),
              ),
            ),
          ],
        ),
        if (pendingCustomerCount > 0) ...[
          const SizedBox(height: 16),
          _EmphasisBanner(
            title: 'Karar bekleyen teklifler var',
            body:
                '$pendingCustomerCount talepte usta seçimi sizi bekliyor. Doğrudan ilgili görünüme geçebilirsiniz.',
            actionLabel: 'Karar ekranına git',
            onPressed: () => onOpenRequestsTab(filter: 'decision'),
          ),
        ],
        const SizedBox(height: 24),
        const _SectionTitle(
          title: 'Son hareketler',
          subtitle:
              'Son aktif talepleriniz burada özetlenir; anlaşma kayıtları ise ayrı görünümde tutulur.',
        ),
        if (totalActiveCount > recentRequests.length &&
            recentRequests.isNotEmpty)
          Padding(
            padding: const EdgeInsets.only(bottom: 12),
            child: Text(
              'Toplam $totalActiveCount açık kaydın var. Ana sayfada yalnızca son ${recentRequests.length} tanesi gösteriliyor.',
              style: TextStyle(color: BrandConfig.textMutedOf(context)),
            ),
          ),
        if (recentRequests.isEmpty)
          const _EmptyStateCard(
            title: 'Henüz kayıtlı talep yok',
            body:
                'İlk talebinizi oluşturduğunuzda burada kısa özetini göreceksiniz.',
          ),
        for (final item in recentRequests)
          _RequestCard(
            title: (item['service_type'] ?? 'Talep').toString(),
            badge: _customerRequestBadgeLabel(item),
            subtitle:
                '${(item['request_code'] ?? '').toString()} · ${(item['city'] ?? '').toString()} / ${(item['district'] ?? '').toString()}',
            meta: _customerRequestMeta(item),
            flowStepLabel: _requestFlowStepLabel(item),
            flowTitle: _requestFlowTitle(item),
            flowNextAction: _requestFlowNextAction(item),
            flowTone: _requestFlowTone(item),
            body: _summarizeRequestDetails((item['details'] ?? '').toString()),
            actionLabel: 'Detayı aç',
            onPressed: () {
              final requestId = (item['id'] as num?)?.toInt() ?? 0;
              if (requestId > 0) {
                return onOpenRequestDetail(requestId);
              }
              return Future<void>.value();
            },
          ),
        if (customerRequestCount > recentRequests.length)
          FilledButton.tonalIcon(
            onPressed: () => onOpenRequestsTab(),
            icon: const Icon(Icons.arrow_forward_rounded),
            label: const Text('Tüm taleplerimi aç'),
          ),
        if ((sessionSnapshot['unread_notifications_count'] as num? ?? 0) > 0)
          Padding(
            padding: const EdgeInsets.only(top: 10),
            child: Text(
              'Bildirimler sekmesinde sizi bekleyen yeni hareketler var.',
              style: TextStyle(color: BrandConfig.textMutedOf(context)),
            ),
          ),
      ];
    }

    return [
      const _SectionHero(
        title: 'Müşteri paneli',
        subtitle: 'Ana akışınızı uygulama içinde, hızlı ekranlarla yönetin.',
      ),
      if (onOpenWebPanel != null) ...[
        const SizedBox(height: 16),
        FilledButton.tonalIcon(
          onPressed: onOpenWebPanel,
          icon: const Icon(Icons.language_rounded),
          label: const Text('Site panelini aç'),
        ),
      ],
      const SizedBox(height: 16),
      Row(
        children: [
          Expanded(
            child: _QuickActionCard(
              icon: Icons.search_rounded,
              title: 'Usta bul',
              subtitle: 'Filtrele, karşılaştır, detayını aç.',
              onTap: onOpenProviderCatalog,
            ),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: _QuickActionCard(
              icon: Icons.add_circle_outline_rounded,
              title: 'Talep oluştur',
              subtitle: 'Yeni iş talebini uygulamadan gönder.',
              onTap: () => onCreateRequest(),
            ),
          ),
        ],
      ),
      const SizedBox(height: 16),
      Row(
        children: [
          Expanded(
            child: _MetricCard(
              label: 'Son aktif talepler',
              value: '$previewActiveCount',
              tone: 'primary',
            ),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: _MetricCard(
              label: 'Seçim bekleyen',
              value: '$pendingCustomerCount',
              tone: 'warning',
            ),
          ),
        ],
      ),
      const SizedBox(height: 10),
      Row(
        children: [
          Expanded(
            child: _MetricCard(
              label: 'Devam eden',
              value: '$matchedCount',
              tone: 'success',
            ),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: _MetricCard(
              label: 'Yanıt bekliyor',
              value: '$waitingProviderCount',
              tone: 'muted',
            ),
          ),
        ],
      ),
      const SizedBox(height: 24),
      const _SectionTitle(
        title: 'Taleplerim',
        subtitle:
            'Mesajlaşma açılan işlerde doğrudan uygulama içi sohbete geçebilirsiniz.',
      ),
      if (totalActiveCount > customerRequests.length &&
          customerRequests.isNotEmpty)
        Padding(
          padding: const EdgeInsets.only(bottom: 12),
          child: Text(
            'Toplam $totalActiveCount açık kaydın var. Ana sayfa yalnızca son ${customerRequests.length} tanesini özetler.',
            style: TextStyle(color: BrandConfig.textMutedOf(context)),
          ),
        ),
      if (customerRequests.isEmpty)
        const _EmptyStateCard(
          title: 'Henüz kayıtlı talep yok',
          body:
              'Yeni talepleriniz web tarafında oluşur ve burada takip edilir.',
        ),
      for (final item in customerRequests)
        _RequestCard(
          title: (item['service_type'] ?? 'Talep').toString(),
          badge: _customerRequestBadgeLabel(item),
          subtitle:
              '${(item['request_code'] ?? '').toString()} · ${(item['city'] ?? '').toString()} / ${(item['district'] ?? '').toString()}',
          meta:
              'Usta: ${(item['matched_provider_name'] ?? '-').toString()} · Okunmamış: ${(item['unread_messages'] ?? 0).toString()}',
          flowStepLabel: _requestFlowStepLabel(item),
          flowTitle: _requestFlowTitle(item),
          flowNextAction: _requestFlowNextAction(item),
          flowTone: _requestFlowTone(item),
          body: (item['details'] ?? '').toString(),
          actionLabel: 'Detayı aç',
          onPressed: () {
            final requestId = (item['id'] as num?)?.toInt() ?? 0;
            if (requestId > 0) {
              return onOpenRequestDetail(requestId);
            }
            return Future<void>.value();
          },
        ),
      if ((sessionSnapshot['unread_notifications_count'] as num? ?? 0) > 0)
        Padding(
          padding: const EdgeInsets.only(top: 8),
          child: Text(
            'Bildirimler sekmesinde sizi bekleyen yeni hareketler var.',
            style: TextStyle(color: BrandConfig.textMutedOf(context)),
          ),
        ),
    ];
  }

  List<Widget> _buildProviderContent(BuildContext context) {
    final snapshot = dashboardPayload['snapshot'] is Map<String, dynamic>
        ? dashboardPayload['snapshot'] as Map<String, dynamic>
        : const <String, dynamic>{};
    final summary = dashboardPayload['summary'] is Map<String, dynamic>
        ? dashboardPayload['summary'] as Map<String, dynamic>
        : const <String, dynamic>{};
    final membership = dashboardPayload['membership'] is Map<String, dynamic>
        ? dashboardPayload['membership'] as Map<String, dynamic>
        : const <String, dynamic>{};

    return [
      const _SectionHero(
        title: 'Usta paneli',
        subtitle:
            'Bildirimler, aktif işler ve iletişim akışı artık uygulama içinde açılıyor.',
      ),
      const SizedBox(height: 16),
      Card(
        child: Padding(
          padding: const EdgeInsets.all(18),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                (membership['title'] ?? 'Üyelik durumu').toString(),
                style: Theme.of(context).textTheme.titleMedium?.copyWith(
                      fontWeight: FontWeight.w700,
                    ),
              ),
              const SizedBox(height: 8),
              Text(
                (membership['message'] ?? '').toString(),
                style: TextStyle(
                  color: BrandConfig.textMutedOf(context),
                  height: 1.4,
                ),
              ),
            ],
          ),
        ),
      ),
      const SizedBox(height: 14),
      Row(
        children: [
          Expanded(
            child: _MetricCard(
              label: 'Yeni teklifler',
              value: '${snapshot['pending_offers_count'] ?? 0}',
              tone: 'primary',
            ),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: _MetricCard(
              label: 'Seçim bekleyen',
              value: '${snapshot['waiting_customer_selection_count'] ?? 0}',
              tone: 'warning',
            ),
          ),
        ],
      ),
      const SizedBox(height: 10),
      Row(
        children: [
          Expanded(
            child: _MetricCard(
              label: 'Aktif sohbet',
              value:
                  '${_summaryCount(summary, 'active_threads_count', providerActiveThreads.length)}',
              tone: 'success',
            ),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: _MetricCard(
              label: 'Randevu onayı',
              value: '${snapshot['pending_appointments_count'] ?? 0}',
              tone: 'muted',
            ),
          ),
        ],
      ),
      const SizedBox(height: 24),
      const _SectionTitle(
        title: 'Hemen cevap ver',
        subtitle:
            'Teklifleri doğrudan uygulama içinden onaylayabilir, reddedebilir veya geri çekebilirsiniz.',
      ),
      if (providerPendingOffers.isEmpty)
        const _EmptyStateCard(
          title: 'Bekleyen teklif yok',
          body: 'Yeni gelen talepler burada listelenecek.',
        ),
      for (final item in providerPendingOffers)
        _RequestCard(
          title: (item['service_type'] ?? 'Talep').toString(),
          badge: 'bekliyor',
          subtitle:
              '${(item['request_code'] ?? '').toString()} · ${(item['city'] ?? '').toString()} / ${(item['district'] ?? '').toString()}',
          meta: (item['customer_name'] ?? '').toString(),
          flowStepLabel: _requestFlowStepLabel(item),
          flowTitle: _requestFlowTitle(item),
          flowNextAction: _requestFlowNextAction(item),
          flowTone: _requestFlowTone(item),
          body: _summarizeRequestDetails((item['details'] ?? '').toString()),
          actionLabel: 'Detayı aç',
          extraActions: [
            if (item['can_accept'] == true)
              FilledButton.tonalIcon(
                onPressed: isProviderActionBusy(
                  'offer:${(item['id'] as num?)?.toInt() ?? 0}:accept',
                )
                    ? null
                    : () {
                        onAcceptProviderOffer(item);
                      },
                icon: const Icon(Icons.check_circle_outline_rounded),
                label: const Text('Onayla'),
              ),
            if (item['can_reject'] == true)
              OutlinedButton.icon(
                onPressed: isProviderActionBusy(
                  'offer:${(item['id'] as num?)?.toInt() ?? 0}:reject',
                )
                    ? null
                    : () {
                        onRejectProviderOffer(item);
                      },
                icon: const Icon(Icons.close_rounded),
                label: const Text('Reddet'),
              ),
          ],
          onPressed: () {
            final requestId =
                (item['service_request_id'] as num?)?.toInt() ?? 0;
            if (requestId > 0) {
              return onOpenRequestDetail(requestId);
            }
            return Future<void>.value();
          },
        ),
      if (providerWaitingSelection.isNotEmpty) ...[
        const SizedBox(height: 24),
        const _SectionTitle(
          title: 'Müşteri kararı bekleyenler',
          subtitle:
              'Verdiğiniz tekliflerin durumunu uygulama içinden takip edin.',
        ),
        for (final item in providerWaitingSelection)
          _RequestCard(
            title: (item['service_type'] ?? 'Talep').toString(),
            badge: 'seçim',
            subtitle:
                '${(item['request_code'] ?? '').toString()} · ${(item['customer_name'] ?? '').toString()}',
            meta: 'Durum: müşteri seçimi bekleniyor',
            flowStepLabel: _requestFlowStepLabel(item),
            flowTitle: _requestFlowTitle(item),
            flowNextAction: _requestFlowNextAction(item),
            flowTone: _requestFlowTone(item),
            body: _summarizeRequestDetails((item['details'] ?? '').toString()),
            actionLabel: 'Detayı aç',
            extraActions: [
              if (item['can_withdraw'] == true)
                OutlinedButton.icon(
                  onPressed: isProviderActionBusy(
                    'offer:${(item['id'] as num?)?.toInt() ?? 0}:withdraw',
                  )
                      ? null
                      : () {
                          onWithdrawProviderOffer(item);
                        },
                  icon: const Icon(Icons.undo_rounded),
                  label: const Text('Geri çek'),
                ),
            ],
            onPressed: () {
              final requestId =
                  (item['service_request_id'] as num?)?.toInt() ?? 0;
              if (requestId > 0) {
                return onOpenRequestDetail(requestId);
              }
              return Future<void>.value();
            },
          ),
      ],
      const SizedBox(height: 24),
      const _SectionTitle(
        title: 'Aktif işler',
        subtitle: 'Mesajlar artık uygulama içinde açılıyor.',
      ),
      if (providerActiveThreads.isEmpty)
        const _EmptyStateCard(
          title: 'Aktif iş bulunmuyor',
          body: 'Eşleşen bir talep olduğunda bu bölüm aktif hale gelir.',
        ),
      for (final item in providerActiveThreads)
        _RequestCard(
          title: (item['service_type'] ?? 'İş').toString(),
          badge: 'aktif',
          subtitle:
              '${(item['request_code'] ?? '').toString()} · ${(item['city'] ?? '').toString()} / ${(item['district'] ?? '').toString()}',
          meta:
              '${(item['customer_name'] ?? '').toString()} · Okunmamış: ${(item['unread_messages'] ?? 0).toString()}',
          flowStepLabel: _requestFlowStepLabel(item),
          flowTitle: _requestFlowTitle(item),
          flowNextAction: _requestFlowNextAction(item),
          flowTone: _requestFlowTone(item),
          body: _summarizeRequestDetails((item['details'] ?? '').toString()),
          actionLabel: 'Detayı aç',
          extraActions: [
            OutlinedButton.icon(
              onPressed: () {
                final requestId = (item['id'] as num?)?.toInt() ?? 0;
                if (requestId > 0) {
                  onOpenThread(
                    requestId: requestId,
                    title: (item['service_type'] ?? 'İş').toString(),
                    subtitle:
                        '${(item['city'] ?? '').toString()} / ${(item['district'] ?? '').toString()}',
                  );
                }
              },
              icon: const Icon(Icons.chat_bubble_outline_rounded),
              label: const Text('Mesajları aç'),
            ),
          ],
          onPressed: () {
            final requestId = (item['id'] as num?)?.toInt() ?? 0;
            if (requestId > 0) {
              return onOpenRequestDetail(requestId);
            }
            return Future<void>.value();
          },
        ),
      if (providerPendingAppointments.isNotEmpty) ...[
        const SizedBox(height: 24),
        const _SectionTitle(
          title: 'Bekleyen randevular',
          subtitle:
              'Onay, red ve tamamlama adımlarını uygulama içinde tamamlayın.',
        ),
        for (final item in providerPendingAppointments)
          _RequestCard(
            title: (item['service_type'] ?? 'Randevu').toString(),
            badge: _appointmentStatusLabel((item['status'] ?? '').toString()),
            subtitle:
                '${(item['request_code'] ?? '').toString()} · ${(item['customer_name'] ?? '').toString()}',
            meta:
                'Planlanan zaman: ${(item['scheduled_for'] ?? '').toString()}',
            flowStepLabel: _requestFlowStepLabel(item),
            flowTitle: _requestFlowTitle(item),
            flowNextAction: _requestFlowNextAction(item),
            flowTone: _requestFlowTone(item),
            body: _summarizeRequestDetails((item['details'] ?? '').toString()),
            actionLabel: 'Detayı aç',
            extraActions: [
              if (item['can_confirm'] == true)
                FilledButton.tonalIcon(
                  onPressed: isProviderActionBusy(
                    'appointment:${(item['id'] as num?)?.toInt() ?? 0}:confirm',
                  )
                      ? null
                      : () {
                          onConfirmProviderAppointment(item);
                        },
                  icon: const Icon(Icons.event_available_rounded),
                  label: const Text('Onayla'),
                ),
              if (item['can_reject'] == true)
                OutlinedButton.icon(
                  onPressed: isProviderActionBusy(
                    'appointment:${(item['id'] as num?)?.toInt() ?? 0}:reject',
                  )
                      ? null
                      : () {
                          onRejectProviderAppointment(item);
                        },
                  icon: const Icon(Icons.event_busy_rounded),
                  label: const Text('Reddet'),
                ),
              if (item['can_complete'] == true)
                OutlinedButton.icon(
                  onPressed: isProviderActionBusy(
                    'appointment:${(item['id'] as num?)?.toInt() ?? 0}:complete',
                  )
                      ? null
                      : () {
                          onCompleteProviderAppointment(item);
                        },
                  icon: const Icon(Icons.task_alt_rounded),
                  label: const Text('Bitir'),
                ),
            ],
            onPressed: () {
              final requestId =
                  (item['service_request_id'] as num?)?.toInt() ?? 0;
              if (requestId > 0) {
                return onOpenRequestDetail(requestId);
              }
              return Future<void>.value();
            },
          ),
      ],
    ];
  }
}

class _ProviderWorkTab extends StatelessWidget {
  const _ProviderWorkTab({
    super.key,
    required this.loading,
    required this.error,
    required this.selectedFilter,
    required this.summary,
    required this.providerPendingOffers,
    required this.providerWaitingSelection,
    required this.providerActiveThreads,
    required this.providerPendingAppointments,
    required this.providerAgreements,
    required this.agreementsLoadingMore,
    required this.hasMoreAgreements,
    required this.onRefresh,
    required this.onFilterChanged,
    required this.onLoadMoreAgreements,
    required this.onOpenThread,
    required this.onOpenRequestDetail,
    required this.isProviderActionBusy,
    required this.onAcceptProviderOffer,
    required this.onRejectProviderOffer,
    required this.onWithdrawProviderOffer,
    required this.onConfirmProviderAppointment,
    required this.onRejectProviderAppointment,
    required this.onCompleteProviderAppointment,
  });

  final bool loading;
  final String? error;
  final String selectedFilter;
  final Map<String, dynamic> summary;
  final List<Map<String, dynamic>> providerPendingOffers;
  final List<Map<String, dynamic>> providerWaitingSelection;
  final List<Map<String, dynamic>> providerActiveThreads;
  final List<Map<String, dynamic>> providerPendingAppointments;
  final List<Map<String, dynamic>> providerAgreements;
  final bool agreementsLoadingMore;
  final bool hasMoreAgreements;
  final Future<void> Function() onRefresh;
  final Future<void> Function(String filter) onFilterChanged;
  final Future<void> Function() onLoadMoreAgreements;
  final Future<void> Function({
    required int requestId,
    required String title,
    required String subtitle,
  }) onOpenThread;
  final Future<void> Function(int requestId) onOpenRequestDetail;
  final bool Function(String key) isProviderActionBusy;
  final Future<void> Function(Map<String, dynamic> item) onAcceptProviderOffer;
  final Future<void> Function(Map<String, dynamic> item) onRejectProviderOffer;
  final Future<void> Function(Map<String, dynamic> item)
      onWithdrawProviderOffer;
  final Future<void> Function(Map<String, dynamic> item)
      onConfirmProviderAppointment;
  final Future<void> Function(Map<String, dynamic> item)
      onRejectProviderAppointment;
  final Future<void> Function(Map<String, dynamic> item)
      onCompleteProviderAppointment;

  @override
  Widget build(BuildContext context) {
    if (loading) {
      return const Center(child: CircularProgressIndicator());
    }
    if (error != null) {
      return _ErrorState(message: error!, onRetry: onRefresh);
    }

    final queueCount = _summaryCount(
            summary, 'pending_offers_count', providerPendingOffers.length) +
        _summaryCount(
          summary,
          'waiting_customer_selection_count',
          providerWaitingSelection.length,
        ) +
        _summaryCount(
          summary,
          'pending_appointments_count',
          providerPendingAppointments.length,
        );
    final activeCount = _summaryCount(
      summary,
      'active_threads_count',
      providerActiveThreads.length,
    );
    final agreementCount =
        _summaryCount(summary, 'agreements_count', providerAgreements.length);

    return RefreshIndicator(
      onRefresh: onRefresh,
      child: ListView(
        padding: const EdgeInsets.fromLTRB(16, 12, 16, 24),
        children: [
          const _SectionHero(
            title: 'İşlerim',
            subtitle:
                'Biriken talepler, aktif işler ve tamamlananlar dahil tüm anlaşmalar burada birlikte takip edilir.',
          ),
          const SizedBox(height: 16),
          Row(
            children: [
              Expanded(
                child: _MetricCard(
                  label: 'Biriken işler',
                  value: '$queueCount',
                  tone: 'warning',
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: _MetricCard(
                  label: 'Aktif işler',
                  value: '$activeCount',
                  tone: 'success',
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          _MetricCard(
            label: 'Anlaşmalar',
            value: '$agreementCount',
            tone: 'primary',
          ),
          const SizedBox(height: 18),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              _CategoryChip(
                label: 'Biriken • $queueCount',
                selected: selectedFilter == 'queue',
                onTap: () => onFilterChanged('queue'),
              ),
              _CategoryChip(
                label: 'Aktif işler • $activeCount',
                selected: selectedFilter == 'active',
                onTap: () => onFilterChanged('active'),
              ),
              _CategoryChip(
                label: 'Anlaşmalar • $agreementCount',
                selected: selectedFilter == 'history',
                onTap: () => onFilterChanged('history'),
              ),
            ],
          ),
          const SizedBox(height: 24),
          ...switch (selectedFilter) {
            'active' => _buildActiveContent(),
            'history' => _buildHistoryContent(),
            _ => _buildQueueContent(),
          },
        ],
      ),
    );
  }

  List<Widget> _buildQueueContent() {
    final queueCount = providerPendingOffers.length +
        providerWaitingSelection.length +
        providerPendingAppointments.length;
    if (queueCount == 0) {
      return const [
        _EmptyStateCard(
          title: 'Biriken iş yok',
          body:
              'Yeni talepler, müşteri kararı bekleyen teklifler ve randevu onayları burada toplanacak.',
        ),
      ];
    }

    return [
      const _SectionTitle(
        title: 'Biriken talepler',
        subtitle:
            'Önce yanıt bekleyen işleri görün; ardından karar ve randevu adımlarını tamamlayın.',
      ),
      if (providerPendingOffers.isNotEmpty) ...[
        const SizedBox(height: 6),
        const _SectionTitle(
          title: 'Yeni talepler',
          subtitle: 'Size yeni iletilen ve yanıtınızı bekleyen işler.',
        ),
        for (final item in providerPendingOffers)
          _RequestCard(
            title: (item['service_type'] ?? 'Talep').toString(),
            badge: 'bekliyor',
            subtitle:
                '${(item['request_code'] ?? '').toString()} · ${(item['city'] ?? '').toString()} / ${(item['district'] ?? '').toString()}',
            meta: (item['customer_name'] ?? '').toString(),
            flowStepLabel: _requestFlowStepLabel(item),
            flowTitle: _requestFlowTitle(item),
            flowNextAction: _requestFlowNextAction(item),
            flowTone: _requestFlowTone(item),
            body: _summarizeRequestDetails((item['details'] ?? '').toString()),
            actionLabel: 'Detayı aç',
            extraActions: [
              if (item['can_accept'] == true)
                FilledButton.tonalIcon(
                  onPressed: isProviderActionBusy(
                    'offer:${(item['id'] as num?)?.toInt() ?? 0}:accept',
                  )
                      ? null
                      : () => onAcceptProviderOffer(item),
                  icon: const Icon(Icons.check_circle_outline_rounded),
                  label: const Text('Onayla'),
                ),
              if (item['can_reject'] == true)
                OutlinedButton.icon(
                  onPressed: isProviderActionBusy(
                    'offer:${(item['id'] as num?)?.toInt() ?? 0}:reject',
                  )
                      ? null
                      : () => onRejectProviderOffer(item),
                  icon: const Icon(Icons.close_rounded),
                  label: const Text('Reddet'),
                ),
            ],
            onPressed: () {
              final requestId =
                  (item['service_request_id'] as num?)?.toInt() ?? 0;
              if (requestId > 0) {
                return onOpenRequestDetail(requestId);
              }
              return Future<void>.value();
            },
          ),
      ],
      if (providerWaitingSelection.isNotEmpty) ...[
        const SizedBox(height: 12),
        const _SectionTitle(
          title: 'Müşteri kararı bekleyenler',
          subtitle:
              'Teklifiniz müşteriye ulaştı; seçilene kadar buradan takip edin.',
        ),
        for (final item in providerWaitingSelection)
          _RequestCard(
            title: (item['service_type'] ?? 'Talep').toString(),
            badge: 'seçim',
            subtitle:
                '${(item['request_code'] ?? '').toString()} · ${(item['customer_name'] ?? '').toString()}',
            meta: 'Durum: müşteri seçimi bekleniyor',
            flowStepLabel: _requestFlowStepLabel(item),
            flowTitle: _requestFlowTitle(item),
            flowNextAction: _requestFlowNextAction(item),
            flowTone: _requestFlowTone(item),
            body: _summarizeRequestDetails((item['details'] ?? '').toString()),
            actionLabel: 'Detayı aç',
            extraActions: [
              if (item['can_withdraw'] == true)
                OutlinedButton.icon(
                  onPressed: isProviderActionBusy(
                    'offer:${(item['id'] as num?)?.toInt() ?? 0}:withdraw',
                  )
                      ? null
                      : () => onWithdrawProviderOffer(item),
                  icon: const Icon(Icons.undo_rounded),
                  label: const Text('Geri çek'),
                ),
            ],
            onPressed: () {
              final requestId =
                  (item['service_request_id'] as num?)?.toInt() ?? 0;
              if (requestId > 0) {
                return onOpenRequestDetail(requestId);
              }
              return Future<void>.value();
            },
          ),
      ],
      if (providerPendingAppointments.isNotEmpty) ...[
        const SizedBox(height: 12),
        const _SectionTitle(
          title: 'Bekleyen randevular',
          subtitle:
              'Onay, red ve tamamlama gibi randevu aksiyonlarını buradan yönetin.',
        ),
        for (final item in providerPendingAppointments)
          _RequestCard(
            title: (item['service_type'] ?? 'Randevu').toString(),
            badge: _appointmentStatusLabel((item['status'] ?? '').toString()),
            subtitle:
                '${(item['request_code'] ?? '').toString()} · ${(item['customer_name'] ?? '').toString()}',
            meta:
                'Planlanan zaman: ${(item['scheduled_for'] ?? '').toString()}',
            flowStepLabel: _requestFlowStepLabel(item),
            flowTitle: _requestFlowTitle(item),
            flowNextAction: _requestFlowNextAction(item),
            flowTone: _requestFlowTone(item),
            body: _summarizeRequestDetails((item['details'] ?? '').toString()),
            actionLabel: 'Detayı aç',
            extraActions: [
              if (item['can_confirm'] == true)
                FilledButton.tonalIcon(
                  onPressed: isProviderActionBusy(
                    'appointment:${(item['id'] as num?)?.toInt() ?? 0}:confirm',
                  )
                      ? null
                      : () => onConfirmProviderAppointment(item),
                  icon: const Icon(Icons.event_available_rounded),
                  label: const Text('Onayla'),
                ),
              if (item['can_reject'] == true)
                OutlinedButton.icon(
                  onPressed: isProviderActionBusy(
                    'appointment:${(item['id'] as num?)?.toInt() ?? 0}:reject',
                  )
                      ? null
                      : () => onRejectProviderAppointment(item),
                  icon: const Icon(Icons.event_busy_rounded),
                  label: const Text('Reddet'),
                ),
              if (item['can_complete'] == true)
                OutlinedButton.icon(
                  onPressed: isProviderActionBusy(
                    'appointment:${(item['id'] as num?)?.toInt() ?? 0}:complete',
                  )
                      ? null
                      : () => onCompleteProviderAppointment(item),
                  icon: const Icon(Icons.task_alt_rounded),
                  label: const Text('Bitir'),
                ),
            ],
            onPressed: () {
              final requestId =
                  (item['service_request_id'] as num?)?.toInt() ?? 0;
              if (requestId > 0) {
                return onOpenRequestDetail(requestId);
              }
              return Future<void>.value();
            },
          ),
      ],
    ];
  }

  List<Widget> _buildActiveContent() {
    if (providerActiveThreads.isEmpty) {
      return const [
        _EmptyStateCard(
          title: 'Aktif iş bulunmuyor',
          body: 'Eşleşen bir talep olduğunda bu alan otomatik olarak dolacak.',
        ),
      ];
    }

    return [
      const _SectionTitle(
        title: 'Aktif işler',
        subtitle:
            'Mesajlaşma açık olan işleri buradan yönetin; detay ve sohbet aynı akışta kalsın.',
      ),
      for (final item in providerActiveThreads)
        _RequestCard(
          title: (item['service_type'] ?? 'İş').toString(),
          badge: 'aktif',
          subtitle:
              '${(item['request_code'] ?? '').toString()} · ${(item['city'] ?? '').toString()} / ${(item['district'] ?? '').toString()}',
          meta:
              '${(item['customer_name'] ?? '').toString()} · Okunmamış: ${(item['unread_messages'] ?? 0).toString()}',
          flowStepLabel: _requestFlowStepLabel(item),
          flowTitle: _requestFlowTitle(item),
          flowNextAction: _requestFlowNextAction(item),
          flowTone: _requestFlowTone(item),
          body: _summarizeRequestDetails((item['details'] ?? '').toString()),
          actionLabel: 'Detayı aç',
          extraActions: [
            OutlinedButton.icon(
              onPressed: () {
                final requestId = (item['id'] as num?)?.toInt() ?? 0;
                if (requestId > 0) {
                  onOpenThread(
                    requestId: requestId,
                    title: (item['service_type'] ?? 'İş').toString(),
                    subtitle:
                        '${(item['city'] ?? '').toString()} / ${(item['district'] ?? '').toString()}',
                  );
                }
              },
              icon: const Icon(Icons.chat_bubble_outline_rounded),
              label: const Text('Mesajları aç'),
            ),
          ],
          onPressed: () {
            final requestId = (item['id'] as num?)?.toInt() ?? 0;
            if (requestId > 0) {
              return onOpenRequestDetail(requestId);
            }
            return Future<void>.value();
          },
        ),
    ];
  }

  List<Widget> _buildHistoryContent() {
    final agreementCount =
        _summaryCount(summary, 'agreements_count', providerAgreements.length);
    if (providerAgreements.isEmpty) {
      return const [
        _EmptyStateCard(
          title: 'Anlaşma geçmişi boş',
          body:
              'Webdeki Anlaşmalar ekranında görünen eşleşmeler burada da listelenecek.',
        ),
      ];
    }

    return [
      const _SectionTitle(
        title: 'Anlaşma geçmişi',
        subtitle:
            'Eşleşen, tamamlanan ve iptal edilen tüm anlaşmalar webdeki mantıkla burada tutulur.',
      ),
      for (final item in providerAgreements)
        _RequestCard(
          title: (item['service_type'] ?? 'İş').toString(),
          badge: _providerAgreementBadgeLabel(item),
          subtitle:
              '${(item['request_code'] ?? '').toString()} · ${(item['city'] ?? '').toString()} / ${(item['district'] ?? '').toString()}',
          meta: _providerAgreementMeta(item),
          flowStepLabel: _requestFlowStepLabel(item),
          flowTitle: _requestFlowTitle(item),
          flowNextAction: _requestFlowNextAction(item),
          flowTone: _requestFlowTone(item),
          body: _summarizeRequestDetails((item['details'] ?? '').toString()),
          actionLabel: 'Detayı aç',
          extraActions: [
            if ((item['status'] ?? '').toString() == 'matched')
              FilledButton.tonal(
                onPressed: () {
                  final requestId = (item['id'] as num?)?.toInt() ?? 0;
                  if (requestId > 0) {
                    onOpenThread(
                      requestId: requestId,
                      title: (item['service_type'] ?? 'İş').toString(),
                      subtitle:
                          '${(item['city'] ?? '').toString()} / ${(item['district'] ?? '').toString()}',
                    );
                  }
                },
                child: const Text('Mesajlar'),
              ),
          ],
          onPressed: () {
            final requestId = (item['id'] as num?)?.toInt() ?? 0;
            if (requestId > 0) {
              return onOpenRequestDetail(requestId);
            }
            return Future<void>.value();
          },
        ),
      if (hasMoreAgreements || agreementsLoadingMore)
        _PagedLoadMoreCard(
          loadedCount: providerAgreements.length,
          totalCount: agreementCount,
          loading: agreementsLoadingMore,
          onPressed: agreementsLoadingMore ? null : onLoadMoreAgreements,
        ),
    ];
  }
}

class _RequestsTab extends StatelessWidget {
  const _RequestsTab({
    super.key,
    required this.loading,
    required this.error,
    required this.selectedFilter,
    required this.customerRequests,
    required this.customerRequestCount,
    required this.customerActiveCount,
    required this.customerDecisionCount,
    required this.customerInProgressCount,
    required this.customerAgreementCount,
    required this.visibleRequests,
    required this.requestsLoadingMore,
    required this.hasMoreRequests,
    required this.agreementsLoadingMore,
    required this.hasMoreAgreements,
    required this.onRefresh,
    required this.onFilterChanged,
    required this.onLoadMoreRequests,
    required this.onLoadMoreAgreements,
    required this.onOpenRequestDetail,
    required this.onOpenProviderCatalog,
    required this.onCreateRequest,
  });

  final bool loading;
  final String? error;
  final String selectedFilter;
  final List<Map<String, dynamic>> customerRequests;
  final int customerRequestCount;
  final int customerActiveCount;
  final int customerDecisionCount;
  final int customerInProgressCount;
  final int customerAgreementCount;
  final List<Map<String, dynamic>> visibleRequests;
  final bool requestsLoadingMore;
  final bool hasMoreRequests;
  final bool agreementsLoadingMore;
  final bool hasMoreAgreements;
  final Future<void> Function() onRefresh;
  final Future<void> Function(String filter) onFilterChanged;
  final Future<void> Function() onLoadMoreRequests;
  final Future<void> Function() onLoadMoreAgreements;
  final Future<void> Function(int requestId) onOpenRequestDetail;
  final Future<void> Function() onOpenProviderCatalog;
  final Future<void> Function({
    int? preferredProviderId,
    String? preferredProviderName,
  }) onCreateRequest;

  @override
  Widget build(BuildContext context) {
    if (loading) {
      return const Center(child: CircularProgressIndicator());
    }
    if (error != null) {
      return _ErrorState(message: error!, onRetry: onRefresh);
    }

    final inProgressCount = customerInProgressCount;
    final activeCount = customerActiveCount;
    final decisionCount = customerDecisionCount;
    final historyCount = customerAgreementCount;

    return RefreshIndicator(
      onRefresh: onRefresh,
      child: ListView(
        padding: const EdgeInsets.fromLTRB(16, 12, 16, 24),
        children: [
          const _SectionHero(
            title: 'Taleplerim',
            subtitle:
                'Aktif talepler burada kalır. Web sitesindeki Anlaşmalar ekranına karşılık gelen kayıtlar ise ayrı görünümde tutulur.',
          ),
          const SizedBox(height: 16),
          Row(
            children: [
              Expanded(
                child: _MetricCard(
                  label: 'Aktif talepler',
                  value: '$activeCount',
                  tone: 'primary',
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: _MetricCard(
                  label: 'Karar bekleyen',
                  value: '$decisionCount',
                  tone: 'warning',
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          Row(
            children: [
              Expanded(
                child: _MetricCard(
                  label: 'İş sürüyor',
                  value: '$inProgressCount',
                  tone: 'success',
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: _MetricCard(
                  label: 'Anlaşmalar',
                  value: '$historyCount',
                  tone: 'primary',
                ),
              ),
            ],
          ),
          const SizedBox(height: 18),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              _CategoryChip(
                label: 'Aktif talepler • $activeCount',
                selected: selectedFilter == 'active',
                onTap: () => onFilterChanged('active'),
              ),
              _CategoryChip(
                label: 'Karar bekleyen • $decisionCount',
                selected: selectedFilter == 'decision',
                onTap: () => onFilterChanged('decision'),
              ),
              _CategoryChip(
                label: 'İş sürüyor • $inProgressCount',
                selected: selectedFilter == 'in_progress',
                onTap: () => onFilterChanged('in_progress'),
              ),
              _CategoryChip(
                label: 'Anlaşmalar • $historyCount',
                selected: selectedFilter == 'history',
                onTap: () => onFilterChanged('history'),
              ),
            ],
          ),
          if (historyCount > 0 && selectedFilter != 'history') ...[
            const SizedBox(height: 16),
            _EmphasisBanner(
              title: 'Anlaşma görünümü hazır',
              body:
                  '$historyCount eşleşme kaydınız webdeki Anlaşmalar ekranına benzer şekilde ayrı görünümde listeleniyor.',
              actionLabel: 'Anlaşmaları aç',
              onPressed: () => onFilterChanged('history'),
            ),
          ],
          const SizedBox(height: 24),
          const _SectionTitle(
            title: 'Liste',
            subtitle:
                'Web sitesindeki mantığa yakın şekilde, durumlar sade filtrelerle ayrıldı.',
          ),
          if (visibleRequests.isEmpty)
            _EmptyStateCard(
              title: _emptyStateTitleForFilter(selectedFilter),
              body: _emptyStateBodyForFilter(selectedFilter),
            ),
          for (final item in visibleRequests)
            _RequestCard(
              title: (item['service_type'] ?? 'Talep').toString(),
              badge: _customerRequestBadgeLabel(item),
              subtitle:
                  '${(item['request_code'] ?? '').toString()} · ${(item['city'] ?? '').toString()} / ${(item['district'] ?? '').toString()}',
              meta: _customerRequestMeta(item),
              flowStepLabel: _requestFlowStepLabel(item),
              flowTitle: _requestFlowTitle(item),
              flowNextAction: _requestFlowNextAction(item),
              flowTone: _requestFlowTone(item),
              body:
                  _summarizeRequestDetails((item['details'] ?? '').toString()),
              actionLabel: 'Detayı aç',
              onPressed: () {
                final requestId = (item['id'] as num?)?.toInt() ?? 0;
                if (requestId > 0) {
                  return onOpenRequestDetail(requestId);
                }
                return Future<void>.value();
              },
            ),
          if (selectedFilter != 'history' &&
              (hasMoreRequests || requestsLoadingMore))
            _PagedLoadMoreCard(
              loadedCount: customerRequests.length,
              totalCount: customerRequestCount,
              loading: requestsLoadingMore,
              onPressed: requestsLoadingMore ? null : onLoadMoreRequests,
            ),
          if (selectedFilter == 'history' &&
              (hasMoreAgreements || agreementsLoadingMore))
            _PagedLoadMoreCard(
              loadedCount: visibleRequests.length,
              totalCount: customerAgreementCount,
              loading: agreementsLoadingMore,
              onPressed: agreementsLoadingMore ? null : onLoadMoreAgreements,
            ),
          if (customerActiveCount == 0 &&
              customerDecisionCount == 0 &&
              customerInProgressCount == 0 &&
              customerAgreementCount == 0) ...[
            const SizedBox(height: 16),
            Row(
              children: [
                Expanded(
                  child: FilledButton.tonalIcon(
                    onPressed: onOpenProviderCatalog,
                    icon: const Icon(Icons.search_rounded),
                    label: const Text('Usta bul'),
                  ),
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: FilledButton.icon(
                    onPressed: () => onCreateRequest(),
                    icon: const Icon(Icons.add_rounded),
                    label: const Text('Talep oluştur'),
                  ),
                ),
              ],
            ),
          ],
        ],
      ),
    );
  }
}

class _MessagesTab extends StatelessWidget {
  const _MessagesTab({
    super.key,
    required this.isProvider,
    required this.loading,
    required this.error,
    required this.threads,
    required this.onRefresh,
    required this.onOpenThread,
  });

  final bool isProvider;
  final bool loading;
  final String? error;
  final List<Map<String, dynamic>> threads;
  final Future<void> Function() onRefresh;
  final Future<void> Function({
    required int requestId,
    required String title,
    required String subtitle,
  }) onOpenThread;

  @override
  Widget build(BuildContext context) {
    if (loading) {
      return const Center(child: CircularProgressIndicator());
    }
    if (error != null) {
      return _ErrorState(message: error!, onRetry: onRefresh);
    }

    return RefreshIndicator(
      onRefresh: onRefresh,
      child: ListView(
        padding: const EdgeInsets.fromLTRB(16, 12, 16, 24),
        children: [
          _SectionHero(
            title: isProvider ? 'Aktif sohbetler' : 'Mesajlaşma',
            subtitle:
                'Eşleşmiş taleplerde iletişimi uygulama içinden sürdürün.',
          ),
          const SizedBox(height: 20),
          if (threads.isEmpty)
            const _EmptyStateCard(
              title: 'Görüntülenecek sohbet yok',
              body: 'Mesajlaşma açılan talepler burada listelenecek.',
            ),
          for (final item in threads)
            _RequestCard(
              title: (item['service_type'] ?? 'Talep').toString(),
              badge: ((item['unread_messages'] as num?)?.toInt() ?? 0) > 0
                  ? '${item['unread_messages']} yeni'
                  : 'hazır',
              subtitle: isProvider
                  ? '${(item['request_code'] ?? '').toString()} · ${(item['customer_name'] ?? '').toString()}'
                  : '${(item['request_code'] ?? '').toString()} · ${(item['matched_provider_name'] ?? '-').toString()}',
              meta:
                  '${(item['city'] ?? '').toString()} / ${(item['district'] ?? '').toString()}',
              body:
                  'Sohbet detayına giderek yeni mesajlarınızı görebilirsiniz.',
              actionLabel: 'Aç',
              onPressed: () {
                final requestId = (item['id'] as num?)?.toInt() ?? 0;
                return onOpenThread(
                  requestId: requestId,
                  title: (item['service_type'] ?? 'Talep').toString(),
                  subtitle:
                      '${(item['city'] ?? '').toString()} / ${(item['district'] ?? '').toString()}',
                );
              },
            ),
        ],
      ),
    );
  }
}

class _NotificationsTab extends StatelessWidget {
  const _NotificationsTab({
    super.key,
    required this.loading,
    required this.error,
    required this.payload,
    required this.category,
    required this.fallbackToWeb,
    required this.loadingMore,
    required this.hasMore,
    required this.onRefresh,
    required this.onCategoryChanged,
    required this.onLoadMore,
    required this.onOpenNotification,
    required this.onMarkAllRead,
    required this.onOpenWebNotifications,
  });

  final bool loading;
  final String? error;
  final Map<String, dynamic> payload;
  final String category;
  final bool fallbackToWeb;
  final bool loadingMore;
  final bool hasMore;
  final Future<void> Function({String? category}) onRefresh;
  final Future<void> Function(String value) onCategoryChanged;
  final Future<void> Function() onLoadMore;
  final Future<void> Function(Map<String, dynamic> item) onOpenNotification;
  final Future<void> Function() onMarkAllRead;
  final Future<void> Function() onOpenWebNotifications;

  @override
  Widget build(BuildContext context) {
    final results = payload['results'] is List
        ? (payload['results'] as List)
            .whereType<Map>()
            .map((item) =>
                item.map((key, value) => MapEntry(key.toString(), value)))
            .toList()
        : const <Map<String, dynamic>>[];

    if (loading && payload.isEmpty) {
      return const Center(child: CircularProgressIndicator());
    }
    if (fallbackToWeb) {
      return ListView(
        padding: const EdgeInsets.fromLTRB(16, 12, 16, 24),
        children: [
          const _SectionHero(
            title: 'Bildirim merkezi',
            subtitle: 'Canlı sitede bu bölüm web görünümü ile çalışıyor.',
          ),
          const SizedBox(height: 20),
          _FallbackActionCard(
            title: 'Bildirimleri web görünümünde aç',
            body:
                'Canlı backend henüz mobil bildirim API\'sini eksiksiz sunmadığı için bu bölüm site paneline yönlendiriliyor.',
            actionLabel: 'Bildirimleri aç',
            onPressed: onOpenWebNotifications,
          ),
        ],
      );
    }
    if (error != null && payload.isEmpty) {
      return _ErrorState(message: error!, onRetry: () => onRefresh());
    }

    return RefreshIndicator(
      onRefresh: () => onRefresh(),
      child: ListView(
        padding: const EdgeInsets.fromLTRB(16, 12, 16, 24),
        children: [
          const _SectionHero(
            title: 'Bildirim merkezi',
            subtitle:
                'Okunmamış hareketler uygulama içinde filtrelenebilir ve yönlendirilebilir.',
          ),
          const SizedBox(height: 16),
          Row(
            children: [
              Expanded(
                child: _MetricCard(
                  label: 'Okunmamış',
                  value: '${payload['unread_count'] ?? 0}',
                  tone: 'primary',
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: FilledButton.tonalIcon(
                  onPressed: results.isEmpty ? null : onMarkAllRead,
                  icon: const Icon(Icons.done_all_rounded),
                  label: const Text('Tümünü oku'),
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              _CategoryChip(
                label: 'Tümü',
                selected: category == 'all',
                onTap: () => onCategoryChanged('all'),
              ),
              _CategoryChip(
                label: 'Mesaj',
                selected: category == 'message',
                onTap: () => onCategoryChanged('message'),
              ),
              _CategoryChip(
                label: 'Talep',
                selected: category == 'request',
                onTap: () => onCategoryChanged('request'),
              ),
              _CategoryChip(
                label: 'Randevu',
                selected: category == 'appointment',
                onTap: () => onCategoryChanged('appointment'),
              ),
            ],
          ),
          const SizedBox(height: 20),
          if (results.isEmpty)
            const _EmptyStateCard(
              title: 'Yeni bildirim yok',
              body: 'Okunmamış bildirimler bu sekmede listelenecek.',
            ),
          for (final item in results)
            _RequestCard(
              title: (item['title'] ?? 'Bildirim').toString(),
              badge: (item['category'] ?? '').toString(),
              subtitle: (item['counterparty_line'] ?? '').toString(),
              meta: (item['created_at'] ?? '').toString(),
              body: (item['body'] ?? '').toString(),
              actionLabel: 'Aç',
              onPressed: () => onOpenNotification(item),
            ),
          if (hasMore || loadingMore)
            _PagedLoadMoreCard(
              loadedCount: results.length,
              totalCount: (payload['count'] as num?)?.toInt() ?? results.length,
              loading: loadingMore,
              onPressed: loadingMore ? null : onLoadMore,
            ),
          if (error != null && payload.isNotEmpty)
            Padding(
              padding: const EdgeInsets.only(top: 12),
              child: Text(
                error!,
                style: TextStyle(color: BrandConfig.errorTextOf(context)),
              ),
            ),
        ],
      ),
    );
  }
}

class _MoreTab extends StatelessWidget {
  const _MoreTab({
    super.key,
    required this.sessionController,
    required this.themePreference,
    required this.loading,
    required this.saving,
    required this.error,
    required this.notificationPreferences,
    required this.preferencesFallbackToWeb,
    required this.onThemeChanged,
    required this.onRetry,
    required this.onTogglePreference,
    required this.onOpenFallback,
    required this.onLaunchExternal,
  });

  final SessionController sessionController;
  final AppThemePreference themePreference;
  final bool loading;
  final bool saving;
  final String? error;
  final Map<String, dynamic> notificationPreferences;
  final bool preferencesFallbackToWeb;
  final Future<void> Function(AppThemePreference preference) onThemeChanged;
  final Future<void> Function() onRetry;
  final Future<void> Function({
    required String key,
    required bool value,
  }) onTogglePreference;
  final Future<void> Function(String path, {String? pageTitle}) onOpenFallback;
  final Future<void> Function(String rawUri) onLaunchExternal;

  @override
  Widget build(BuildContext context) {
    final session = sessionController.session;
    final user = session?.user ?? const <String, dynamic>{};
    final provider = user['provider'] is Map<String, dynamic>
        ? user['provider'] as Map<String, dynamic>
        : const <String, dynamic>{};

    return ListView(
      padding: const EdgeInsets.fromLTRB(16, 12, 16, 24),
      children: [
        const _SectionHero(
          title: 'Daha fazla',
          subtitle:
              'Bildirim tercihleri, destek ve web görünümü bağlantıları burada toplanır.',
        ),
        const SizedBox(height: 16),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(18),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  (provider['full_name'] ?? user['username'] ?? 'UstaBul')
                      .toString(),
                  style: Theme.of(context).textTheme.titleLarge?.copyWith(
                        fontWeight: FontWeight.w800,
                      ),
                ),
                const SizedBox(height: 8),
                Text(
                  session?.isProvider == true
                      ? 'Usta hesabıyla giriş yapıldı.'
                      : 'Müşteri hesabıyla giriş yapıldı.',
                  style: TextStyle(color: BrandConfig.textMutedOf(context)),
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 20),
        const _SectionTitle(
          title: 'Görünüm',
          subtitle:
              'Uygulamayı aydınlık ya da karanlık tema ile kullanabilirsiniz.',
        ),
        Card(
          child: Column(
            children: [
              _ThemeChoiceTile(
                title: 'Aydınlık mod',
                subtitle: 'Daha açık yüzeyler ve gündüz kullanımı için.',
                selected: themePreference == AppThemePreference.light,
                onTap: () => onThemeChanged(AppThemePreference.light),
              ),
              const Divider(height: 1),
              _ThemeChoiceTile(
                title: 'Karanlık mod',
                subtitle: 'Gece kullanımı için daha düşük parlaklık.',
                selected: themePreference == AppThemePreference.dark,
                onTap: () => onThemeChanged(AppThemePreference.dark),
              ),
            ],
          ),
        ),
        const SizedBox(height: 20),
        const _SectionTitle(
          title: 'Bildirim tercihleri',
          subtitle:
              'Mağaza incelemesi için bildirim ayarlarının uygulama içinde görünür olması gerekir.',
        ),
        if (preferencesFallbackToWeb)
          _FallbackActionCard(
            title: 'Bildirim tercihleri web görünümünde',
            body:
                'Canlı sitede bu ayarlar henüz mobil API yerine hesap ayarları sayfasından yönetiliyor.',
            actionLabel: 'Hesap ayarlarını aç',
            onPressed: () => onOpenFallback(
              '/hesap/ayarlar/?tab=notifications',
              pageTitle: 'Hesap Ayarları',
            ),
          )
        else if (loading)
          const Card(
            child: Padding(
              padding: EdgeInsets.all(18),
              child: Center(child: CircularProgressIndicator()),
            ),
          )
        else ...[
          Card(
            child: Column(
              children: [
                SwitchListTile.adaptive(
                  value:
                      notificationPreferences['allow_message_notifications'] ==
                          true,
                  onChanged: saving
                      ? null
                      : (value) => onTogglePreference(
                            key: 'allow_message_notifications',
                            value: value,
                          ),
                  title: const Text('Mesaj bildirimleri'),
                  subtitle:
                      const Text('Yeni mesajlarda bildirim ve rozet göster.'),
                ),
                const Divider(height: 1),
                SwitchListTile.adaptive(
                  value:
                      notificationPreferences['allow_request_notifications'] ==
                          true,
                  onChanged: saving
                      ? null
                      : (value) => onTogglePreference(
                            key: 'allow_request_notifications',
                            value: value,
                          ),
                  title: const Text('Talep güncellemeleri'),
                  subtitle: const Text('Teklif ve eşleşme durumlarını bildir.'),
                ),
                const Divider(height: 1),
                SwitchListTile.adaptive(
                  value: notificationPreferences[
                          'allow_appointment_notifications'] ==
                      true,
                  onChanged: saving
                      ? null
                      : (value) => onTogglePreference(
                            key: 'allow_appointment_notifications',
                            value: value,
                          ),
                  title: const Text('Randevu bildirimleri'),
                  subtitle: const Text(
                      'Randevu oluşturma ve onay adımlarını bildir.'),
                ),
              ],
            ),
          ),
          if (error != null)
            Padding(
              padding: const EdgeInsets.only(top: 12),
              child: Row(
                children: [
                  Expanded(
                    child: Text(
                      error!,
                      style: TextStyle(color: BrandConfig.errorTextOf(context)),
                    ),
                  ),
                  TextButton(
                    onPressed: onRetry,
                    child: const Text('Tekrar dene'),
                  ),
                ],
              ),
            ),
        ],
        const SizedBox(height: 20),
        const _SectionTitle(
          title: 'Gizlilik ve veri',
          subtitle:
              'Gizlilik politikası ve hesap silme yolları uygulama içinde görünür tutulur.',
        ),
        _ActionTile(
          icon: Icons.privacy_tip_outlined,
          title: 'Gizlilik politikası',
          subtitle: 'Veri işleme ve saklama bilgilerini aç',
          onTap: () => onOpenFallback(
            '/gizlilik-politikasi/',
            pageTitle: 'Gizlilik Politikası',
          ),
        ),
        _ActionTile(
          icon: Icons.delete_forever_outlined,
          title: 'Hesabı sil',
          subtitle: 'Kalıcı silme ekranını aç',
          onTap: () => onOpenFallback(
            '/hesap/ayarlar/?tab=danger',
            pageTitle: 'Hesap Silme',
          ),
        ),
        _ActionTile(
          icon: Icons.manage_accounts_outlined,
          title: 'Hesap silme talebi',
          subtitle: 'Uygulama dışı silme bilgi sayfasını aç',
          onTap: () =>
              onOpenFallback('/hesap-silme/', pageTitle: 'Hesap Silme Talebi'),
        ),
        const SizedBox(height: 20),
        const _SectionTitle(
          title: 'Destek',
          subtitle:
              'Ulaşılabilir destek bilgisi mağaza incelemesinde de güven veren bir işarettir.',
        ),
        _ActionTile(
          icon: Icons.phone_in_talk_rounded,
          title: '0850 000 00 00',
          subtitle: 'Her gün 08:00 - 22:00',
          onTap: () => onLaunchExternal('tel:08500000000'),
        ),
        _ActionTile(
          icon: Icons.mail_outline_rounded,
          title: 'ustabulcyprus@gmail.com',
          subtitle: 'Destek ve geri bildirim',
          onTap: () => onLaunchExternal('mailto:ustabulcyprus@gmail.com'),
        ),
        _ActionTile(
          icon: Icons.support_agent_rounded,
          title: 'Destek merkezi',
          subtitle: 'Web görünümünde aç',
          onTap: () => onOpenFallback('/contact/', pageTitle: 'Destek Merkezi'),
        ),
        const SizedBox(height: 20),
        const _SectionTitle(
          title: 'Web görünümü',
          subtitle:
              'İkincil sayfalar burada açılır; ana kullanımınız uygulama içinde kalır.',
        ),
        _ActionTile(
          icon: Icons.language_rounded,
          title: 'UstaBul sitesi',
          subtitle: 'Ana siteyi uygulama içinde aç',
          onTap: () => onOpenFallback('/', pageTitle: 'UstaBul'),
        ),
        _ActionTile(
          icon: Icons.settings_applications_rounded,
          title: 'Hesap ayarları',
          subtitle: 'Web görünümünde aç',
          onTap: () =>
              onOpenFallback('/hesap/ayarlar/', pageTitle: 'Hesap Ayarları'),
        ),
        const SizedBox(height: 20),
        FilledButton.tonalIcon(
          onPressed: sessionController.logout,
          icon: const Icon(Icons.logout_rounded),
          label: const Text('Çıkış yap'),
        ),
      ],
    );
  }
}

class _SectionHero extends StatelessWidget {
  const _SectionHero({
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

class _SectionTitle extends StatelessWidget {
  const _SectionTitle({
    required this.title,
    required this.subtitle,
  });

  final String title;
  final String subtitle;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            title,
            style: Theme.of(context).textTheme.titleLarge?.copyWith(
                  fontWeight: FontWeight.w800,
                ),
          ),
          const SizedBox(height: 6),
          Text(
            subtitle,
            style: TextStyle(
              color: BrandConfig.textMutedOf(context),
              height: 1.35,
            ),
          ),
        ],
      ),
    );
  }
}

bool _matchesCustomerRequestFilter(Map<String, dynamic> item, String filter) {
  final status = (item['status'] ?? '').toString();
  switch (filter) {
    case 'active':
      return {
        'new',
        'pending_provider',
        'pending_customer',
      }.contains(status);
    case 'waiting':
      return status == 'new' || status == 'pending_provider';
    case 'decision':
      return status == 'pending_customer';
    case 'in_progress':
      return status == 'matched';
    case 'agreements':
      return _isAgreementRecord(item);
    case 'history':
      return _isAgreementRecord(item);
    default:
      return {
        'new',
        'pending_provider',
        'pending_customer',
        'matched',
      }.contains(status);
  }
}

bool _isAgreementRecord(Map<String, dynamic> item) {
  final matchedOfferId = (item['matched_offer_id'] as num?)?.toInt();
  if (matchedOfferId != null && matchedOfferId > 0) {
    return true;
  }
  return ((item['matched_at'] ?? '').toString()).trim().isNotEmpty;
}

String _requestStatusLabel(String status) {
  switch (status) {
    case 'new':
      return 'Yeni';
    case 'pending_provider':
      return 'Usta yanıtı';
    case 'pending_customer':
      return 'Karar bekliyor';
    case 'matched':
      return 'Eşleşti';
    case 'completed':
      return 'Tamamlandı';
    case 'cancelled':
      return 'İptal edildi';
    default:
      return status.isEmpty ? 'Durum' : status;
  }
}

String _appointmentStatusLabel(String status) {
  switch (status) {
    case 'pending':
      return 'Randevu bekliyor';
    case 'pending_customer':
      return 'Randevu onayı';
    case 'confirmed':
      return 'Randevu onaylı';
    case 'rejected':
      return 'Randevu reddedildi';
    case 'cancelled':
      return 'Randevu iptal';
    case 'completed':
      return 'Randevu tamamlandı';
    default:
      return status.isEmpty ? '' : status;
  }
}

String _customerRequestBadgeLabel(Map<String, dynamic> item) {
  final statusUiLabel = (item['status_ui_label'] ?? '').toString().trim();
  if (statusUiLabel.isNotEmpty) {
    return statusUiLabel;
  }
  final appointmentStatus = _appointmentStatusLabel(
    (item['appointment_status'] ?? '').toString(),
  );
  if (appointmentStatus.isNotEmpty &&
      (item['status'] ?? '').toString() == 'matched') {
    return appointmentStatus;
  }
  return _requestStatusLabel((item['status'] ?? '').toString());
}

String _customerRequestMeta(Map<String, dynamic> item) {
  final parts = <String>[];
  final hasFlow = _requestFlowTitle(item).isNotEmpty ||
      _requestFlowNextAction(item).isNotEmpty;
  final providerName = (item['matched_provider_name'] ?? '').toString().trim();
  final matchedAt = (item['matched_at'] ?? '').toString().trim();
  final unreadMessages = (item['unread_messages'] as num?)?.toInt() ?? 0;

  if (!hasFlow) {
    parts.add(_customerRequestStageText(item));
  }

  if (_isAgreementRecord(item) && matchedAt.isNotEmpty) {
    parts.add('Anlaşma: ${_formatIsoDateTime(matchedAt)}');
  }
  if (providerName.isNotEmpty) {
    parts.add('Usta: $providerName');
  } else {
    parts.add('Henüz usta seçilmedi');
  }
  if (unreadMessages > 0) {
    parts.add('$unreadMessages okunmamış');
  }
  return parts.join(' · ');
}

String _formatIsoDateTime(String rawValue) {
  final parsed = DateTime.tryParse(rawValue);
  if (parsed == null) {
    return rawValue;
  }
  final local = parsed.toLocal();
  String two(int value) => value.toString().padLeft(2, '0');
  return '${two(local.day)}.${two(local.month)}.${local.year} ${two(local.hour)}:${two(local.minute)}';
}

int _summaryCount(
  Map<String, dynamic> summary,
  String key,
  int fallback,
) {
  final raw = summary[key];
  if (raw is num) {
    return raw.toInt();
  }
  return fallback;
}

String _providerAgreementBadgeLabel(Map<String, dynamic> item) {
  final statusUiLabel = (item['status_ui_label'] ?? '').toString().trim();
  if (statusUiLabel.isNotEmpty) {
    return statusUiLabel;
  }
  final appointmentStatus = _appointmentStatusLabel(
    (item['appointment_status'] ?? '').toString(),
  );
  if (appointmentStatus.isNotEmpty) {
    return appointmentStatus;
  }
  return _requestStatusLabel((item['status'] ?? '').toString());
}

String _providerAgreementMeta(Map<String, dynamic> item) {
  final parts = <String>[];
  final customerName = (item['customer_name'] ?? '').toString().trim();
  final matchedAt = (item['matched_at'] ?? '').toString().trim();
  final appointmentScheduledFor =
      (item['appointment_scheduled_for'] ?? '').toString().trim();
  final unreadMessages = (item['unread_messages'] as num?)?.toInt() ?? 0;

  if (customerName.isNotEmpty) {
    parts.add(customerName);
  }
  if (matchedAt.isNotEmpty) {
    parts.add('Anlaşma: ${_formatIsoDateTime(matchedAt)}');
  }
  if (appointmentScheduledFor.isNotEmpty) {
    parts.add('Randevu: ${_formatIsoDateTime(appointmentScheduledFor)}');
  } else if ((item['appointment_status'] ?? '').toString().trim().isNotEmpty) {
    parts.add(
      _appointmentStatusLabel((item['appointment_status'] ?? '').toString()),
    );
  }
  if (unreadMessages > 0) {
    parts.add('$unreadMessages okunmamış');
  }
  return parts.join(' · ');
}

String _customerRequestStageText(Map<String, dynamic> item) {
  final status = (item['status'] ?? '').toString();
  final appointmentStatus = (item['appointment_status'] ?? '').toString();

  switch (status) {
    case 'new':
      return 'Aşama: Talep oluşturuldu';
    case 'pending_provider':
      return 'Aşama: Usta yanıtı bekleniyor';
    case 'pending_customer':
      return 'Aşama: Teklifleri inceleyip seçim yapın';
    case 'matched':
      switch (appointmentStatus) {
        case 'pending':
          return 'Aşama: Randevu için usta onayı bekleniyor';
        case 'pending_customer':
          return 'Aşama: Randevuyu sizin onaylamanız bekleniyor';
        case 'confirmed':
          return 'Aşama: Randevu onaylandı, iş sürüyor';
        case 'completed':
          return 'Aşama: İş tamamlandı';
        case 'rejected':
        case 'cancelled':
          return 'Aşama: Yeni randevu planlanabilir';
        default:
          return 'Aşama: Usta seçildi, iş sürüyor';
      }
    case 'completed':
      return 'Aşama: İş tamamlandı';
    case 'cancelled':
      return 'Aşama: Talep iptal edildi';
    default:
      return 'Aşama: Süreç devam ediyor';
  }
}

String _requestFlowStepLabel(Map<String, dynamic> item) {
  return (item['flow_step'] ?? '').toString().trim();
}

String _requestFlowTitle(Map<String, dynamic> item) {
  final value = (item['flow_title'] ?? '').toString().trim();
  if (value.isNotEmpty) {
    return value;
  }

  final stage = _customerRequestStageText(item);
  return stage.startsWith('Aşama: ') ? stage.substring(7) : '';
}

String _requestFlowNextAction(Map<String, dynamic> item) {
  return (item['flow_next_action'] ?? '').toString().trim();
}

String _requestFlowTone(Map<String, dynamic> item) {
  final value = (item['flow_tone'] ?? '').toString().trim();
  return value.isEmpty ? 'muted' : value;
}

int? _requestFlowCurrentStep(String stepLabel) {
  final match = RegExp(r'(\d+)\s*/\s*(\d+)').firstMatch(stepLabel);
  return int.tryParse(match?.group(1) ?? '');
}

int? _requestFlowTotalSteps(String stepLabel) {
  final match = RegExp(r'(\d+)\s*/\s*(\d+)').firstMatch(stepLabel);
  return int.tryParse(match?.group(2) ?? '');
}

Color _requestFlowToneColor(BuildContext context, String tone) {
  switch (tone) {
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

Color _requestFlowAccentColor(
  BuildContext context,
  String stepLabel,
  String tone,
) {
  if (tone == 'danger') {
    return const Color(0xFFB91C1C);
  }
  final currentStep = _requestFlowCurrentStep(stepLabel);
  switch (currentStep) {
    case 1:
      return const Color(0xFFB7791F);
    case 2:
      return const Color(0xFF2563EB);
    case 3:
      return const Color(0xFF0F766E);
    case 4:
      return const Color(0xFF15803D);
    default:
      return _requestFlowToneColor(context, tone);
  }
}

String _summarizeRequestDetails(String text) {
  final normalized = text.trim().replaceAll(RegExp(r'\s+'), ' ');
  if (normalized.length <= 120) {
    return normalized;
  }
  return '${normalized.substring(0, 117)}...';
}

String _emptyStateTitleForFilter(String filter) {
  switch (filter) {
    case 'active':
      return 'Aktif talep yok';
    case 'waiting':
      return 'Yanıt bekleyen talep yok';
    case 'decision':
      return 'Karar bekleyen teklif yok';
    case 'in_progress':
      return 'Devam eden iş yok';
    case 'agreements':
      return 'Henüz anlaşma yok';
    case 'history':
      return 'Henüz anlaşma kaydı yok';
    default:
      return 'Gösterilecek talep yok';
  }
}

String _emptyStateBodyForFilter(String filter) {
  switch (filter) {
    case 'active':
      return 'Yeni açtığınız, ustadan yanıt bekleyen veya sizin kararınızı bekleyen aktif talepler burada görünür.';
    case 'waiting':
      return 'Yeni açtığınız veya ustalardan yanıt bekleyen işler burada listelenir.';
    case 'decision':
      return 'Usta seçimi yapmanız gereken talepler burada toplanır.';
    case 'in_progress':
      return 'Eşleşmiş ve şu anda devam eden işler burada listelenir.';
    case 'agreements':
      return 'Web sitesindeki Anlaşmalar ekranı gibi, eşleşen aktif ve kapanan işler burada tutulur.';
    case 'history':
      return 'Web sitesindeki Anlaşmalar ekranı gibi, aktif eşleşmelerle birlikte tamamlanan ve iptal edilen anlaşmalar burada tutulur.';
    default:
      return 'Yeni bir talep açtığınızda ya da mevcut işleriniz güncellendiğinde bu liste dolacaktır.';
  }
}

class _MetricCard extends StatelessWidget {
  const _MetricCard({
    required this.label,
    required this.value,
    required this.tone,
  });

  final String label;
  final String value;
  final String tone;

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BrandConfig.glassPanelDecorationOf(context, radius: 22),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              label,
              style: TextStyle(color: BrandConfig.textMutedOf(context)),
            ),
            const SizedBox(height: 10),
            Text(
              value,
              style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                    fontWeight: FontWeight.w800,
                  ),
            ),
          ],
        ),
      ),
    );
  }
}

class _SpotlightCard extends StatelessWidget {
  const _SpotlightCard({
    required this.icon,
    required this.title,
    required this.body,
    required this.actionLabel,
    required this.onTap,
  });

  final IconData icon;
  final String title;
  final String body;
  final String actionLabel;
  final Future<void> Function() onTap;

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BrandConfig.glassPanelDecorationOf(context),
      child: InkWell(
        borderRadius: BorderRadius.circular(28),
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.all(18),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(icon, color: BrandConfig.accentOf(context), size: 28),
              const SizedBox(height: 12),
              Text(
                title,
                style: Theme.of(context).textTheme.titleMedium?.copyWith(
                      fontWeight: FontWeight.w800,
                    ),
              ),
              const SizedBox(height: 8),
              Text(
                body,
                style: TextStyle(
                  color: BrandConfig.textMutedOf(context),
                  height: 1.4,
                ),
              ),
              const SizedBox(height: 14),
              FilledButton.tonal(
                onPressed: onTap,
                child: Text(actionLabel),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _QuickActionCard extends StatelessWidget {
  const _QuickActionCard({
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.onTap,
  });

  final IconData icon;
  final String title;
  final String subtitle;
  final Future<void> Function() onTap;

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BrandConfig.glassPanelDecorationOf(context),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          borderRadius: BorderRadius.circular(24),
          onTap: onTap,
          child: Padding(
            padding: const EdgeInsets.all(18),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Container(
                  width: 44,
                  height: 44,
                  decoration: BoxDecoration(
                    color: BrandConfig.accentSoftOf(context),
                    borderRadius: BorderRadius.circular(14),
                  ),
                  alignment: Alignment.center,
                  child: Icon(
                    icon,
                    color: BrandConfig.accentOf(context),
                    size: 24,
                  ),
                ),
                const SizedBox(height: 14),
                Text(
                  title,
                  style: Theme.of(context).textTheme.titleMedium?.copyWith(
                        fontWeight: FontWeight.w700,
                      ),
                ),
                const SizedBox(height: 6),
                Text(
                  subtitle,
                  style: TextStyle(
                    color: BrandConfig.textMutedOf(context),
                    height: 1.35,
                  ),
                ),
                const SizedBox(height: 14),
                Row(
                  children: [
                    Text(
                      'Hemen aç',
                      style: Theme.of(context).textTheme.labelLarge?.copyWith(
                            color: BrandConfig.accentOf(context),
                          ),
                    ),
                    const SizedBox(width: 6),
                    Icon(
                      Icons.arrow_outward_rounded,
                      size: 18,
                      color: BrandConfig.accentOf(context),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _EmphasisBanner extends StatelessWidget {
  const _EmphasisBanner({
    required this.title,
    required this.body,
    required this.actionLabel,
    required this.onPressed,
  });

  final String title;
  final String body;
  final String actionLabel;
  final Future<void> Function() onPressed;

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BrandConfig.glassPanelDecorationOf(context, radius: 26),
      child: Padding(
        padding: const EdgeInsets.all(18),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
              decoration: BoxDecoration(
                color: BrandConfig.accentSoftOf(context),
                borderRadius: BorderRadius.circular(999),
              ),
              child: Text(
                'Öne çıkan adım',
                style: Theme.of(context).textTheme.labelMedium?.copyWith(
                      color: BrandConfig.accentOf(context),
                      fontWeight: FontWeight.w800,
                    ),
              ),
            ),
            const SizedBox(height: 12),
            Text(
              title,
              style: Theme.of(context).textTheme.titleMedium?.copyWith(
                    fontWeight: FontWeight.w800,
                  ),
            ),
            const SizedBox(height: 8),
            Text(
              body,
              style: TextStyle(
                color: BrandConfig.textMutedOf(context),
                height: 1.45,
              ),
            ),
            const SizedBox(height: 14),
            FilledButton.icon(
              onPressed: onPressed,
              icon: const Icon(Icons.arrow_forward_rounded),
              label: Text(actionLabel),
            ),
          ],
        ),
      ),
    );
  }
}

class _RequestCard extends StatelessWidget {
  const _RequestCard({
    required this.title,
    required this.badge,
    required this.subtitle,
    required this.meta,
    required this.body,
    required this.actionLabel,
    required this.onPressed,
    this.extraActions = const <Widget>[],
    this.flowStepLabel = '',
    this.flowTitle = '',
    this.flowNextAction = '',
    this.flowTone = 'muted',
  });

  final String title;
  final String badge;
  final String subtitle;
  final String meta;
  final String body;
  final String actionLabel;
  final Future<void> Function() onPressed;
  final List<Widget> extraActions;
  final String flowStepLabel;
  final String flowTitle;
  final String flowNextAction;
  final String flowTone;

  @override
  Widget build(BuildContext context) {
    final isLightTheme = BrandConfig.isLight(context);
    final hasFlow = flowStepLabel.trim().isNotEmpty ||
        flowTitle.trim().isNotEmpty ||
        flowNextAction.trim().isNotEmpty;
    final flowColor = _requestFlowAccentColor(
      context,
      flowStepLabel,
      flowTone,
    );
    final badgeSurface = BrandConfig.surfaceAltOf(
      context,
    ).withValues(alpha: isLightTheme ? 0.92 : 0.62);
    final badgeBorder = BrandConfig.borderOf(
      context,
    ).withValues(alpha: isLightTheme ? 0.7 : 0.56);
    final stepBadgeSurface =
        flowColor.withValues(alpha: isLightTheme ? 0.12 : 0.18);
    final stepBadgeBorder =
        flowColor.withValues(alpha: isLightTheme ? 0.24 : 0.34);
    final flowSurface = flowColor.withValues(alpha: isLightTheme ? 0.08 : 0.14);
    final flowBorder = flowColor.withValues(alpha: isLightTheme ? 0.22 : 0.30);
    final progressTrack = flowColor.withValues(
      alpha: isLightTheme ? 0.16 : 0.24,
    );
    final progressFill = flowColor;
    final currentStep = _requestFlowCurrentStep(flowStepLabel);
    final totalSteps = _requestFlowTotalSteps(flowStepLabel);
    final progressValue =
        currentStep != null && totalSteps != null && totalSteps > 0
            ? (currentStep / totalSteps).clamp(0.0, 1.0)
            : null;

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
                        title,
                        style:
                            Theme.of(context).textTheme.titleMedium?.copyWith(
                                  fontWeight: FontWeight.w700,
                                ),
                      ),
                      const SizedBox(height: 6),
                      Text(
                        subtitle,
                        style:
                            TextStyle(color: BrandConfig.textMutedOf(context)),
                      ),
                    ],
                  ),
                ),
                const SizedBox(width: 12),
                Column(
                  crossAxisAlignment: CrossAxisAlignment.end,
                  children: [
                    Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 10,
                        vertical: 6,
                      ),
                      decoration: BoxDecoration(
                        color: badgeSurface,
                        borderRadius: BorderRadius.circular(999),
                        border: Border.all(color: badgeBorder),
                      ),
                      child: Text(
                        badge,
                        style: TextStyle(
                          color: BrandConfig.textMutedOf(context),
                          fontSize: 12,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                    ),
                    if (flowStepLabel.trim().isNotEmpty) ...[
                      const SizedBox(height: 8),
                      Container(
                        padding: const EdgeInsets.symmetric(
                          horizontal: 10,
                          vertical: 5,
                        ),
                        decoration: BoxDecoration(
                          color: stepBadgeSurface,
                          borderRadius: BorderRadius.circular(999),
                          border: Border.all(
                            color: stepBadgeBorder,
                          ),
                        ),
                        child: Text(
                          flowStepLabel,
                          style: TextStyle(
                            color: flowColor,
                            fontSize: 11,
                            fontWeight: FontWeight.w800,
                          ),
                        ),
                      ),
                    ],
                  ],
                ),
              ],
            ),
            if (hasFlow) ...[
              const SizedBox(height: 12),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  color: flowSurface,
                  borderRadius: BorderRadius.circular(18),
                  border: Border.all(
                    color: flowBorder,
                  ),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    if (progressValue != null) ...[
                      Text(
                        '$currentStep / $totalSteps adım',
                        style: TextStyle(
                          color: BrandConfig.textMutedOf(context),
                          fontSize: 12,
                          fontWeight: FontWeight.w800,
                        ),
                      ),
                      const SizedBox(height: 8),
                      ClipRRect(
                        borderRadius: BorderRadius.circular(999),
                        child: LinearProgressIndicator(
                          value: progressValue,
                          minHeight: 7,
                          backgroundColor: progressTrack,
                          valueColor: AlwaysStoppedAnimation<Color>(
                            progressFill,
                          ),
                        ),
                      ),
                    ],
                    if (flowTitle.trim().isNotEmpty) ...[
                      const SizedBox(height: 10),
                      Text(
                        flowTitle,
                        style: Theme.of(context).textTheme.titleSmall?.copyWith(
                              fontWeight: FontWeight.w800,
                            ),
                      ),
                    ],
                    if (flowNextAction.trim().isNotEmpty) ...[
                      const SizedBox(height: 6),
                      Text(
                        flowNextAction,
                        style: TextStyle(
                          color: BrandConfig.textMutedOf(context),
                          height: 1.4,
                        ),
                      ),
                    ],
                  ],
                ),
              ),
            ],
            if (meta.trim().isNotEmpty) ...[
              const SizedBox(height: 12),
              Text(
                meta,
                style: TextStyle(color: BrandConfig.textMutedOf(context)),
              ),
            ],
            const SizedBox(height: 10),
            Text(
              body,
              style: TextStyle(
                color: BrandConfig.textOf(context),
                height: 1.4,
              ),
            ),
            const SizedBox(height: 14),
            Align(
              alignment: Alignment.centerLeft,
              child: FilledButton.tonal(
                onPressed: onPressed,
                child: Text(actionLabel),
              ),
            ),
            if (extraActions.isNotEmpty) ...[
              const SizedBox(height: 10),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: extraActions,
              ),
            ],
          ],
        ),
      ),
    );
  }
}

class _ActionTile extends StatelessWidget {
  const _ActionTile({
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.onTap,
  });

  final IconData icon;
  final String title;
  final String subtitle;
  final Future<void> Function() onTap;

  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.only(bottom: 10),
      child: ListTile(
        contentPadding: const EdgeInsets.symmetric(horizontal: 18, vertical: 6),
        leading: Icon(icon, color: BrandConfig.accentOf(context)),
        title: Text(title),
        subtitle: Text(subtitle),
        trailing: const Icon(Icons.chevron_right_rounded),
        onTap: onTap,
      ),
    );
  }
}

class _ThemeChoiceTile extends StatelessWidget {
  const _ThemeChoiceTile({
    required this.title,
    required this.subtitle,
    required this.selected,
    required this.onTap,
  });

  final String title;
  final String subtitle;
  final bool selected;
  final Future<void> Function() onTap;

  @override
  Widget build(BuildContext context) {
    return ListTile(
      contentPadding: const EdgeInsets.symmetric(horizontal: 18, vertical: 6),
      title: Text(title),
      subtitle: Text(subtitle),
      trailing: Icon(
        selected
            ? Icons.check_circle_rounded
            : Icons.radio_button_unchecked_rounded,
        color: selected
            ? BrandConfig.accentOf(context)
            : BrandConfig.textMutedOf(context),
      ),
      onTap: onTap,
    );
  }
}

class _FallbackActionCard extends StatelessWidget {
  const _FallbackActionCard({
    required this.title,
    required this.body,
    required this.actionLabel,
    required this.onPressed,
  });

  final String title;
  final String body;
  final String actionLabel;
  final Future<void> Function() onPressed;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(18),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              title,
              style: Theme.of(context).textTheme.titleMedium?.copyWith(
                    fontWeight: FontWeight.w700,
                  ),
            ),
            const SizedBox(height: 8),
            Text(
              body,
              style: TextStyle(
                color: BrandConfig.textMutedOf(context),
                height: 1.4,
              ),
            ),
            const SizedBox(height: 14),
            FilledButton.tonal(
              onPressed: onPressed,
              child: Text(actionLabel),
            ),
          ],
        ),
      ),
    );
  }
}

class _CategoryChip extends StatelessWidget {
  const _CategoryChip({
    required this.label,
    required this.selected,
    required this.onTap,
  });

  final String label;
  final bool selected;
  final Future<void> Function() onTap;

  @override
  Widget build(BuildContext context) {
    return ChoiceChip(
      label: Text(label),
      selected: selected,
      onSelected: (_) => onTap(),
    );
  }
}

class _EmptyStateCard extends StatelessWidget {
  const _EmptyStateCard({
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
              Icons.inbox_outlined,
              size: 36,
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

class _PagedLoadMoreCard extends StatelessWidget {
  const _PagedLoadMoreCard({
    required this.loadedCount,
    required this.totalCount,
    required this.loading,
    required this.onPressed,
  });

  final int loadedCount;
  final int totalCount;
  final bool loading;
  final Future<void> Function()? onPressed;

  @override
  Widget build(BuildContext context) {
    final remaining = totalCount - loadedCount;
    return Padding(
      padding: const EdgeInsets.only(top: 12),
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            children: [
              Text(
                '$loadedCount / $totalCount anlaşma yüklendi',
                style: Theme.of(context).textTheme.titleSmall?.copyWith(
                      fontWeight: FontWeight.w700,
                    ),
              ),
              const SizedBox(height: 8),
              Text(
                remaining > 0
                    ? '$remaining kayıt daha isteğe bağlı olarak yüklenebilir.'
                    : 'Tüm kayıtlar yüklendi.',
                textAlign: TextAlign.center,
                style: TextStyle(color: BrandConfig.textMutedOf(context)),
              ),
              const SizedBox(height: 12),
              if (loading)
                const SizedBox(
                  height: 24,
                  width: 24,
                  child: CircularProgressIndicator(strokeWidth: 2.4),
                )
              else
                OutlinedButton.icon(
                  onPressed: onPressed == null ? null : () => onPressed!(),
                  icon: const Icon(Icons.expand_more_rounded),
                  label: const Text('Daha fazla yükle'),
                ),
            ],
          ),
        ),
      ),
    );
  }
}

class _ErrorState extends StatelessWidget {
  const _ErrorState({
    required this.message,
    required this.onRetry,
  });

  final String message;
  final Future<void> Function() onRetry;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              Icons.cloud_off_rounded,
              size: 42,
              color: BrandConfig.textMutedOf(context),
            ),
            const SizedBox(height: 12),
            Text(
              'Veri yüklenemedi',
              style: Theme.of(context).textTheme.titleLarge?.copyWith(
                    fontWeight: FontWeight.w700,
                  ),
            ),
            const SizedBox(height: 8),
            Text(
              message,
              textAlign: TextAlign.center,
              style: TextStyle(color: BrandConfig.textMutedOf(context)),
            ),
            const SizedBox(height: 16),
            FilledButton.icon(
              onPressed: onRetry,
              icon: const Icon(Icons.refresh_rounded),
              label: const Text('Tekrar dene'),
            ),
          ],
        ),
      ),
    );
  }
}
