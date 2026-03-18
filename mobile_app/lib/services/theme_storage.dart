import 'package:flutter_secure_storage/flutter_secure_storage.dart';

enum AppThemePreference {
  dark,
  light,
}

class ThemeStorage {
  static const _themeKey = 'ustabul_mobile_theme';

  final FlutterSecureStorage _storage = const FlutterSecureStorage();

  Future<AppThemePreference> loadThemePreference() async {
    final raw = await _storage.read(key: _themeKey);
    return switch (raw) {
      'light' => AppThemePreference.light,
      _ => AppThemePreference.dark,
    };
  }

  Future<void> saveThemePreference(AppThemePreference preference) async {
    await _storage.write(key: _themeKey, value: preference.name);
  }
}
