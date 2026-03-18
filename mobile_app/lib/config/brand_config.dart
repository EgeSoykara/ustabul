import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

@immutable
class BrandPalette {
  const BrandPalette({
    required this.background,
    required this.surface,
    required this.surfaceAlt,
    required this.text,
    required this.textMuted,
    required this.accent,
    required this.accentSoft,
    required this.border,
    required this.inputFill,
    required this.heroGradient,
    required this.heroTextMuted,
    required this.errorSurface,
    required this.errorText,
    required this.warningSurface,
    required this.floatingSurface,
    required this.floatingShadow,
  });

  final Color background;
  final Color surface;
  final Color surfaceAlt;
  final Color text;
  final Color textMuted;
  final Color accent;
  final Color accentSoft;
  final Color border;
  final Color inputFill;
  final LinearGradient heroGradient;
  final Color heroTextMuted;
  final Color errorSurface;
  final Color errorText;
  final Color warningSurface;
  final Color floatingSurface;
  final Color floatingShadow;
}

class BrandConfig {
  static const Color background = Color(0xFF0B1220);
  static const Color surface = Color(0xFF121C2F);
  static const Color text = Color(0xFFF8FAFC);
  static const Color textMuted = Color(0xFFB8C4D9);
  static const Color accent = Color(0xFF0E7490);

  static const BrandPalette _darkPalette = BrandPalette(
    background: Color(0xFF0B1220),
    surface: Color(0xFF121C2F),
    surfaceAlt: Color(0xFF18253A),
    text: Color(0xFFF8FAFC),
    textMuted: Color(0xFFB8C4D9),
    accent: Color(0xFF0E7490),
    accentSoft: Color(0x1F29B6D1),
    border: Color(0x1F8CA3B3),
    inputFill: Color(0xFF111A2B),
    heroGradient: LinearGradient(
      colors: [
        Color(0xFF0E7490),
        Color(0xFF0F172A),
      ],
      begin: Alignment.topLeft,
      end: Alignment.bottomRight,
    ),
    heroTextMuted: Color(0xFFE2E8F0),
    errorSurface: Color(0xFF3B1118),
    errorText: Color(0xFFFDA4AF),
    warningSurface: Color(0x33F97316),
    floatingSurface: Color(0xD9121C2F),
    floatingShadow: Color(0x55000000),
  );

  static const BrandPalette _lightPalette = BrandPalette(
    background: Color(0xFFF3F7FB),
    surface: Color(0xFFFFFFFF),
    surfaceAlt: Color(0xFFE8EEF5),
    text: Color(0xFF0F172A),
    textMuted: Color(0xFF526277),
    accent: Color(0xFF0E7490),
    accentSoft: Color(0x1F0E7490),
    border: Color(0xFFD6E0EA),
    inputFill: Color(0xFFF8FBFD),
    heroGradient: LinearGradient(
      colors: [
        Color(0xFF0E7490),
        Color(0xFF1D4ED8),
      ],
      begin: Alignment.topLeft,
      end: Alignment.bottomRight,
    ),
    heroTextMuted: Color(0xFFE0F2FE),
    errorSurface: Color(0xFFFDECEC),
    errorText: Color(0xFFB42318),
    warningSurface: Color(0xFFFFEDD5),
    floatingSurface: Color(0xF2FFFFFF),
    floatingShadow: Color(0x1F0F172A),
  );

  static BrandPalette paletteFor(Brightness brightness) {
    return brightness == Brightness.light ? _lightPalette : _darkPalette;
  }

  static BrandPalette paletteOf(BuildContext context) {
    return paletteFor(Theme.of(context).brightness);
  }

  static ThemeData themeFor(Brightness brightness) {
    final palette = paletteFor(brightness);
    final colorScheme = ColorScheme.fromSeed(
      seedColor: palette.accent,
      brightness: brightness,
    ).copyWith(
      primary: palette.accent,
      secondary: palette.accent,
      secondaryContainer: palette.accentSoft,
      onSecondaryContainer: palette.text,
      surface: palette.surface,
      onSurface: palette.text,
      onSurfaceVariant: palette.textMuted,
      outline: palette.border,
      error: brightness == Brightness.light
          ? const Color(0xFFB42318)
          : const Color(0xFFFB7185),
      surfaceContainerHighest: palette.surfaceAlt,
    );

    return ThemeData(
      brightness: brightness,
      colorScheme: colorScheme,
      scaffoldBackgroundColor: palette.background,
      appBarTheme: AppBarTheme(
        backgroundColor: palette.background,
        foregroundColor: palette.text,
        elevation: 0,
        centerTitle: false,
      ),
      cardTheme: CardThemeData(
        color: palette.surface,
        elevation: 0,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(24),
          side: BorderSide(color: palette.border),
        ),
      ),
      dividerTheme: DividerThemeData(
        color: palette.border.withValues(alpha: 0.9),
        thickness: 1,
      ),
      listTileTheme: ListTileThemeData(
        iconColor: palette.accent,
        textColor: palette.text,
      ),
      navigationBarTheme: NavigationBarThemeData(
        backgroundColor: palette.background,
        indicatorColor: palette.accentSoft,
        labelTextStyle: WidgetStateProperty.resolveWith((states) {
          return TextStyle(
            color: states.contains(WidgetState.selected)
                ? palette.text
                : palette.textMuted,
            fontWeight: states.contains(WidgetState.selected)
                ? FontWeight.w700
                : FontWeight.w600,
          );
        }),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: palette.inputFill,
        labelStyle: TextStyle(color: palette.textMuted),
        hintStyle: TextStyle(color: palette.textMuted),
        prefixIconColor: palette.textMuted,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(18),
          borderSide: BorderSide(color: palette.border),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(18),
          borderSide: BorderSide(color: palette.border),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(18),
          borderSide: BorderSide(color: palette.accent, width: 1.4),
        ),
        errorBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(18),
          borderSide: BorderSide(color: colorScheme.error),
        ),
        focusedErrorBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(18),
          borderSide: BorderSide(color: colorScheme.error, width: 1.4),
        ),
      ),
      progressIndicatorTheme: ProgressIndicatorThemeData(
        color: palette.accent,
        linearTrackColor: palette.accentSoft,
      ),
      snackBarTheme: SnackBarThemeData(
        backgroundColor: brightness == Brightness.light
            ? const Color(0xFF0F172A)
            : const Color(0xFF1E293B),
        contentTextStyle: const TextStyle(color: Colors.white),
      ),
      chipTheme: ChipThemeData(
        backgroundColor: palette.surfaceAlt,
        disabledColor: palette.surfaceAlt,
        selectedColor: palette.accentSoft,
        secondarySelectedColor: palette.accentSoft,
        side: BorderSide(color: palette.border),
        labelStyle: TextStyle(color: palette.text),
        secondaryLabelStyle: TextStyle(color: palette.text),
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      ),
      filledButtonTheme: FilledButtonThemeData(
        style: FilledButton.styleFrom(
          backgroundColor: palette.accent,
          foregroundColor: Colors.white,
          disabledBackgroundColor: palette.accent.withValues(alpha: 0.4),
          disabledForegroundColor: Colors.white70,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(18),
          ),
        ),
      ),
      textButtonTheme: TextButtonThemeData(
        style: TextButton.styleFrom(
          foregroundColor: palette.accent,
        ),
      ),
      switchTheme: SwitchThemeData(
        thumbColor: WidgetStateProperty.resolveWith((states) {
          if (states.contains(WidgetState.selected)) {
            return palette.accent;
          }
          return palette.surfaceAlt;
        }),
        trackColor: WidgetStateProperty.resolveWith((states) {
          if (states.contains(WidgetState.selected)) {
            return palette.accent.withValues(alpha: 0.35);
          }
          return palette.surfaceAlt;
        }),
      ),
      useMaterial3: true,
    );
  }

  static SystemUiOverlayStyle overlayStyleFor(Brightness brightness) {
    final palette = paletteFor(brightness);
    final iconBrightness =
        brightness == Brightness.light ? Brightness.dark : Brightness.light;
    return SystemUiOverlayStyle(
      statusBarColor: palette.background,
      statusBarIconBrightness: iconBrightness,
      statusBarBrightness: brightness,
      systemNavigationBarColor: palette.background,
      systemNavigationBarIconBrightness: iconBrightness,
      systemNavigationBarDividerColor: palette.background,
    );
  }

  static bool isLight(BuildContext context) =>
      Theme.of(context).brightness == Brightness.light;

  static Color backgroundOf(BuildContext context) =>
      paletteOf(context).background;
  static Color surfaceOf(BuildContext context) => paletteOf(context).surface;
  static Color surfaceAltOf(BuildContext context) =>
      paletteOf(context).surfaceAlt;
  static Color textOf(BuildContext context) => paletteOf(context).text;
  static Color textMutedOf(BuildContext context) =>
      paletteOf(context).textMuted;
  static Color accentOf(BuildContext context) => paletteOf(context).accent;
  static Color accentSoftOf(BuildContext context) =>
      paletteOf(context).accentSoft;
  static Color borderOf(BuildContext context) => paletteOf(context).border;
  static Color inputFillOf(BuildContext context) =>
      paletteOf(context).inputFill;
  static LinearGradient heroGradientOf(BuildContext context) =>
      paletteOf(context).heroGradient;
  static Color heroTextMutedOf(BuildContext context) =>
      paletteOf(context).heroTextMuted;
  static Color errorSurfaceOf(BuildContext context) =>
      paletteOf(context).errorSurface;
  static Color errorTextOf(BuildContext context) =>
      paletteOf(context).errorText;
  static Color warningSurfaceOf(BuildContext context) =>
      paletteOf(context).warningSurface;
  static Color floatingSurfaceOf(BuildContext context) =>
      paletteOf(context).floatingSurface;
  static Color floatingShadowOf(BuildContext context) =>
      paletteOf(context).floatingShadow;
}
