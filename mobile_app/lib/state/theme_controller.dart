import 'package:flutter/material.dart';

import '../services/theme_storage.dart';

class ThemeController extends ChangeNotifier {
  ThemeController({required ThemeStorage storage}) : _storage = storage;

  final ThemeStorage _storage;

  AppThemePreference _preference = AppThemePreference.dark;

  AppThemePreference get preference => _preference;

  ThemeMode get themeMode {
    return _preference == AppThemePreference.light
        ? ThemeMode.light
        : ThemeMode.dark;
  }

  Brightness get brightness {
    return _preference == AppThemePreference.light
        ? Brightness.light
        : Brightness.dark;
  }

  Future<void> initialize() async {
    _preference = await _storage.loadThemePreference();
    notifyListeners();
  }

  Future<void> setPreference(AppThemePreference preference) async {
    if (_preference == preference) {
      return;
    }
    _preference = preference;
    notifyListeners();
    await _storage.saveThemePreference(preference);
  }
}
