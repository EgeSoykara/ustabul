import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'config/app_config.dart';
import 'config/brand_config.dart';
import 'screens/home_screen.dart';
import 'screens/login_screen.dart';
import 'services/api_client.dart';
import 'services/auth_service.dart';
import 'services/auth_storage.dart';
import 'services/mobile_data_service.dart';
import 'services/push_service.dart';
import 'services/theme_storage.dart';
import 'services/web_auth_service.dart';
import 'state/session_controller.dart';
import 'state/theme_controller.dart';
import 'widgets/brand_backdrop.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  PushService.registerBackgroundHandler();
  await SystemChrome.setPreferredOrientations([
    DeviceOrientation.portraitUp,
  ]);

  final themeController = ThemeController(storage: ThemeStorage());
  await themeController.initialize();
  SystemChrome.setSystemUIOverlayStyle(
    BrandConfig.overlayStyleFor(themeController.brightness),
  );

  runApp(UstaBulMobileApp(themeController: themeController));
}

class UstaBulMobileApp extends StatefulWidget {
  const UstaBulMobileApp({
    super.key,
    required this.themeController,
  });

  final ThemeController themeController;

  @override
  State<UstaBulMobileApp> createState() => _UstaBulMobileAppState();
}

class _UstaBulMobileAppState extends State<UstaBulMobileApp> {
  late final ApiClient _apiClient;
  late final AuthService _authService;
  late final AuthStorage _authStorage;
  late final PushService _pushService;
  late final MobileDataService _mobileDataService;
  late final WebAuthService _webAuthService;
  late final SessionController _sessionController;

  @override
  void initState() {
    super.initState();
    _apiClient = ApiClient(baseUrl: AppConfig.apiBaseUrl);
    _authService = AuthService(_apiClient);
    _authStorage = AuthStorage();
    _pushService = PushService(_authService);
    _mobileDataService = MobileDataService(_apiClient);
    _webAuthService = WebAuthService(siteUrl: AppConfig.siteUrl);
    _sessionController = SessionController(
      authService: _authService,
      authStorage: _authStorage,
      pushService: _pushService,
      webAuthService: _webAuthService,
    );
    widget.themeController.addListener(_handleThemeChanged);
    _sessionController.initialize();
  }

  void _handleThemeChanged() {
    SystemChrome.setSystemUIOverlayStyle(
      BrandConfig.overlayStyleFor(widget.themeController.brightness),
    );
  }

  @override
  void dispose() {
    widget.themeController.removeListener(_handleThemeChanged);
    widget.themeController.dispose();
    _sessionController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: widget.themeController,
      builder: (context, _) {
        return MaterialApp(
          title: 'UstaBul',
          debugShowCheckedModeBanner: false,
          theme: BrandConfig.themeFor(Brightness.light),
          darkTheme: BrandConfig.themeFor(Brightness.dark),
          themeMode: widget.themeController.themeMode,
          home: _AppGate(
            sessionController: _sessionController,
            dataService: _mobileDataService,
            themeController: widget.themeController,
          ),
        );
      },
    );
  }
}

class _AppGate extends StatelessWidget {
  const _AppGate({
    required this.sessionController,
    required this.dataService,
    required this.themeController,
  });

  final SessionController sessionController;
  final MobileDataService dataService;
  final ThemeController themeController;

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: sessionController,
      builder: (context, _) {
        if (sessionController.isInitializing) {
          return const _BootScreen();
        }
        if (!sessionController.isAuthenticated) {
          return LoginScreen(sessionController: sessionController);
        }
        return HomeScreen(
          sessionController: sessionController,
          dataService: dataService,
          themeController: themeController,
        );
      },
    );
  }
}

class _BootScreen extends StatelessWidget {
  const _BootScreen();

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Scaffold(
      body: BrandBackdrop(
        child: Center(
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 32),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Container(
                  width: 108,
                  height: 108,
                  decoration: BrandConfig.glassPanelDecorationOf(
                    context,
                    radius: 34,
                  ),
                  child: Icon(
                    Icons.home_repair_service_rounded,
                    size: 44,
                    color: BrandConfig.textOf(context),
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
                  'Mobil deneyim hazırlanıyor',
                  style: theme.textTheme.bodyMedium?.copyWith(
                    color: BrandConfig.textMutedOf(context),
                  ),
                ),
                const SizedBox(height: 22),
                const SizedBox(
                  width: 160,
                  child: LinearProgressIndicator(minHeight: 6),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
