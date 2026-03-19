import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';

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
    required this.backgroundGradient,
    required this.heroGradient,
    required this.heroTextMuted,
    required this.errorSurface,
    required this.errorText,
    required this.warningSurface,
    required this.floatingSurface,
    required this.floatingShadow,
    required this.cardShadow,
    required this.orbPrimary,
    required this.orbAccent,
    required this.ctaBackground,
    required this.ctaForeground,
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
  final LinearGradient backgroundGradient;
  final LinearGradient heroGradient;
  final Color heroTextMuted;
  final Color errorSurface;
  final Color errorText;
  final Color warningSurface;
  final Color floatingSurface;
  final Color floatingShadow;
  final Color cardShadow;
  final Color orbPrimary;
  final Color orbAccent;
  final Color ctaBackground;
  final Color ctaForeground;
}

class BrandConfig {
  static const Color background = Color(0xFF050B1A);
  static const Color surface = Color(0xD90F172A);
  static const Color text = Color(0xFFF8FAFC);
  static const Color textMuted = Color(0xFFB8C4D9);
  static const Color accent = Color(0xFF0E7490);

  static const BrandPalette _darkPalette = BrandPalette(
    background: Color(0xFF050B1A),
    surface: Color(0xD90F172A),
    surfaceAlt: Color(0xFF172335),
    text: Color(0xFFF8FAFC),
    textMuted: Color(0xFFB8C4D9),
    accent: Color(0xFF38BDF8),
    accentSoft: Color(0x2638BDF8),
    border: Color(0x4247B6D8),
    inputFill: Color(0xCC0B1628),
    backgroundGradient: LinearGradient(
      colors: [
        Color(0xFF050B1A),
        Color(0xFF0A1223),
      ],
      begin: Alignment.topCenter,
      end: Alignment.bottomCenter,
    ),
    heroGradient: LinearGradient(
      colors: [
        Color(0xFF0A1223),
        Color(0xFF0E7490),
      ],
      begin: Alignment.topLeft,
      end: Alignment.bottomRight,
    ),
    heroTextMuted: Color(0xFFD9E8F4),
    errorSurface: Color(0xFF3B1118),
    errorText: Color(0xFFFDA4AF),
    warningSurface: Color(0x33F97316),
    floatingSurface: Color(0xE60F172A),
    floatingShadow: Color(0x66000000),
    cardShadow: Color(0x66000000),
    orbPrimary: Color(0x2638BDF8),
    orbAccent: Color(0x26F97316),
    ctaBackground: Color(0xFF050505),
    ctaForeground: Color(0xFFF8FAFC),
  );

  static const BrandPalette _lightPalette = BrandPalette(
    background: Color(0xFFF9FDFF),
    surface: Color(0xEBFFFFFF),
    surfaceAlt: Color(0xFFF4F9FD),
    text: Color(0xFF0F172A),
    textMuted: Color(0xFF526277),
    accent: Color(0xFF0E7490),
    accentSoft: Color(0x190E7490),
    border: Color(0x330E7490),
    inputFill: Color(0xF7FFFFFF),
    backgroundGradient: LinearGradient(
      colors: [
        Color(0xFFF9FDFF),
        Color(0xFFEEF6FF),
      ],
      begin: Alignment.topCenter,
      end: Alignment.bottomCenter,
    ),
    heroGradient: LinearGradient(
      colors: [
        Color(0xFF0E7490),
        Color(0xFF111827),
      ],
      begin: Alignment.topLeft,
      end: Alignment.bottomRight,
    ),
    heroTextMuted: Color(0xFFE2E8F0),
    errorSurface: Color(0xFFFDECEC),
    errorText: Color(0xFFB42318),
    warningSurface: Color(0xFFFFEDD5),
    floatingSurface: Color(0xF2FFFFFF),
    floatingShadow: Color(0x1A0F172A),
    cardShadow: Color(0x1A0F172A),
    orbPrimary: Color(0x1F0E7490),
    orbAccent: Color(0x22F97316),
    ctaBackground: Color(0xFF0F1115),
    ctaForeground: Color(0xFFF8FAFC),
  );

  static BrandPalette paletteFor(Brightness brightness) {
    return brightness == Brightness.light ? _lightPalette : _darkPalette;
  }

  static BrandPalette paletteOf(BuildContext context) {
    return paletteFor(Theme.of(context).brightness);
  }

  static TextTheme _textThemeFor(TextTheme base, BrandPalette palette) {
    final bodyTheme = GoogleFonts.manropeTextTheme(base).apply(
      bodyColor: palette.text,
      displayColor: palette.text,
    );
    final headingTheme = GoogleFonts.soraTextTheme(bodyTheme).apply(
      bodyColor: palette.text,
      displayColor: palette.text,
    );
    return bodyTheme.copyWith(
      displayLarge: headingTheme.displayLarge?.copyWith(
        fontWeight: FontWeight.w700,
        letterSpacing: -1.1,
      ),
      displayMedium: headingTheme.displayMedium?.copyWith(
        fontWeight: FontWeight.w700,
        letterSpacing: -0.9,
      ),
      displaySmall: headingTheme.displaySmall?.copyWith(
        fontWeight: FontWeight.w700,
        letterSpacing: -0.8,
      ),
      headlineLarge: headingTheme.headlineLarge?.copyWith(
        fontWeight: FontWeight.w700,
        letterSpacing: -0.8,
      ),
      headlineMedium: headingTheme.headlineMedium?.copyWith(
        fontWeight: FontWeight.w700,
        letterSpacing: -0.7,
      ),
      headlineSmall: headingTheme.headlineSmall?.copyWith(
        fontWeight: FontWeight.w700,
        letterSpacing: -0.6,
      ),
      titleLarge: headingTheme.titleLarge?.copyWith(
        fontWeight: FontWeight.w700,
        letterSpacing: -0.4,
      ),
      titleMedium: headingTheme.titleMedium?.copyWith(
        fontWeight: FontWeight.w700,
        letterSpacing: -0.2,
      ),
      titleSmall: headingTheme.titleSmall?.copyWith(
        fontWeight: FontWeight.w700,
      ),
      bodyLarge: bodyTheme.bodyLarge?.copyWith(height: 1.45),
      bodyMedium: bodyTheme.bodyMedium?.copyWith(height: 1.45),
      bodySmall: bodyTheme.bodySmall?.copyWith(height: 1.4),
      labelLarge: bodyTheme.labelLarge?.copyWith(fontWeight: FontWeight.w700),
      labelMedium: bodyTheme.labelMedium?.copyWith(fontWeight: FontWeight.w700),
    );
  }

  static ThemeData themeFor(Brightness brightness) {
    final palette = paletteFor(brightness);
    final colorScheme = ColorScheme.fromSeed(
      seedColor: palette.accent,
      brightness: brightness,
    ).copyWith(
      primary: palette.accent,
      secondary: palette.accent,
      tertiary: const Color(0xFFF97316),
      secondaryContainer: palette.accentSoft,
      onSecondaryContainer: palette.text,
      surface: palette.surface,
      onSurface: palette.text,
      onSurfaceVariant: palette.textMuted,
      outline: palette.border,
      shadow: palette.cardShadow,
      error: brightness == Brightness.light
          ? const Color(0xFFB42318)
          : const Color(0xFFFB7185),
      surfaceContainer: palette.surfaceAlt,
      surfaceContainerHighest: palette.surfaceAlt,
    );

    final baseTheme = ThemeData(
      useMaterial3: true,
      brightness: brightness,
      colorScheme: colorScheme,
    );
    final textTheme = _textThemeFor(baseTheme.textTheme, palette);

    return baseTheme.copyWith(
      scaffoldBackgroundColor: palette.background,
      canvasColor: palette.background,
      textTheme: textTheme,
      primaryTextTheme: textTheme,
      appBarTheme: AppBarTheme(
        backgroundColor: palette.background.withValues(
          alpha: brightness == Brightness.light ? 0.88 : 0.76,
        ),
        foregroundColor: palette.text,
        elevation: 0,
        scrolledUnderElevation: 0,
        centerTitle: false,
        surfaceTintColor: Colors.transparent,
        titleTextStyle: textTheme.titleLarge?.copyWith(
          color: palette.text,
          fontWeight: FontWeight.w700,
        ),
      ),
      cardTheme: CardThemeData(
        color: palette.surface,
        elevation: brightness == Brightness.light ? 4 : 2,
        shadowColor: palette.cardShadow,
        surfaceTintColor: Colors.transparent,
        margin: EdgeInsets.zero,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(24),
          side: BorderSide(color: palette.border),
        ),
      ),
      dialogTheme: DialogThemeData(
        backgroundColor: palette.surface,
        surfaceTintColor: Colors.transparent,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(24),
          side: BorderSide(color: palette.border),
        ),
      ),
      dividerTheme: DividerThemeData(
        color: palette.border.withValues(alpha: 0.92),
        thickness: 1,
      ),
      listTileTheme: ListTileThemeData(
        iconColor: palette.accent,
        textColor: palette.text,
      ),
      navigationBarTheme: NavigationBarThemeData(
        backgroundColor: palette.floatingSurface,
        shadowColor: palette.floatingShadow,
        surfaceTintColor: Colors.transparent,
        indicatorColor: palette.accentSoft.withValues(alpha: 0.95),
        elevation: 14,
        height: 74,
        labelTextStyle: WidgetStateProperty.resolveWith((states) {
          return textTheme.labelMedium?.copyWith(
                color: states.contains(WidgetState.selected)
                    ? palette.text
                    : palette.textMuted,
                fontWeight: states.contains(WidgetState.selected)
                    ? FontWeight.w700
                    : FontWeight.w600,
              ) ??
              TextStyle(
                color: states.contains(WidgetState.selected)
                    ? palette.text
                    : palette.textMuted,
              );
        }),
        iconTheme: WidgetStateProperty.resolveWith((states) {
          return IconThemeData(
            color: states.contains(WidgetState.selected)
                ? palette.text
                : palette.textMuted,
          );
        }),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: palette.inputFill,
        labelStyle: TextStyle(color: palette.textMuted),
        hintStyle: TextStyle(color: palette.textMuted),
        prefixIconColor: palette.textMuted,
        contentPadding:
            const EdgeInsets.symmetric(horizontal: 18, vertical: 18),
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
        backgroundColor:
            brightness == Brightness.light ? const Color(0xFF0F172A) : surface,
        contentTextStyle: GoogleFonts.manrope(
          color: Colors.white,
          fontWeight: FontWeight.w600,
        ),
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(18)),
      ),
      chipTheme: ChipThemeData(
        backgroundColor: palette.surfaceAlt,
        disabledColor: palette.surfaceAlt,
        selectedColor: palette.accentSoft,
        secondarySelectedColor: palette.accentSoft,
        side: BorderSide(color: palette.border),
        labelStyle: textTheme.labelLarge?.copyWith(color: palette.text),
        secondaryLabelStyle:
            textTheme.labelLarge?.copyWith(color: palette.text),
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(999)),
      ),
      filledButtonTheme: FilledButtonThemeData(
        style: FilledButton.styleFrom(
          backgroundColor: palette.ctaBackground,
          foregroundColor: palette.ctaForeground,
          disabledBackgroundColor: palette.ctaBackground.withValues(alpha: 0.4),
          disabledForegroundColor: palette.ctaForeground.withValues(alpha: 0.7),
          elevation: 0,
          padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 16),
          textStyle: textTheme.titleSmall?.copyWith(
            fontWeight: FontWeight.w700,
          ),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(18),
          ),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          foregroundColor: palette.text,
          backgroundColor: palette.surface.withValues(
            alpha: brightness == Brightness.light ? 0.74 : 0.28,
          ),
          side: BorderSide(color: palette.border),
          padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 16),
          textStyle: textTheme.titleSmall?.copyWith(
            fontWeight: FontWeight.w700,
          ),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(18),
          ),
        ),
      ),
      textButtonTheme: TextButtonThemeData(
        style: TextButton.styleFrom(
          foregroundColor: palette.accent,
          textStyle: textTheme.labelLarge,
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
    );
  }

  static SystemUiOverlayStyle overlayStyleFor(Brightness brightness) {
    final palette = paletteFor(brightness);
    final iconBrightness =
        brightness == Brightness.light ? Brightness.dark : Brightness.light;
    return SystemUiOverlayStyle(
      statusBarColor: Colors.transparent,
      statusBarIconBrightness: iconBrightness,
      statusBarBrightness: brightness,
      systemNavigationBarColor: palette.background,
      systemNavigationBarIconBrightness: iconBrightness,
      systemNavigationBarDividerColor: Colors.transparent,
    );
  }

  static bool isLight(BuildContext context) =>
      Theme.of(context).brightness == Brightness.light;

  static BoxDecoration backgroundDecorationOf(BuildContext context) {
    return BoxDecoration(gradient: paletteOf(context).backgroundGradient);
  }

  static BoxDecoration heroPanelDecorationOf(
    BuildContext context, {
    double radius = 28,
  }) {
    final palette = paletteOf(context);
    return BoxDecoration(
      borderRadius: BorderRadius.circular(radius),
      gradient: palette.heroGradient,
      border: Border.all(color: palette.border.withValues(alpha: 0.9)),
      boxShadow: [
        BoxShadow(
          color: palette.cardShadow,
          blurRadius: 36,
          offset: const Offset(0, 18),
        ),
      ],
    );
  }

  static BoxDecoration glassPanelDecorationOf(
    BuildContext context, {
    double radius = 24,
  }) {
    final palette = paletteOf(context);
    return BoxDecoration(
      color: palette.surface,
      borderRadius: BorderRadius.circular(radius),
      border: Border.all(color: palette.border),
      boxShadow: [
        BoxShadow(
          color: palette.cardShadow.withValues(alpha: 0.72),
          blurRadius: 28,
          offset: const Offset(0, 14),
        ),
      ],
    );
  }

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
  static LinearGradient backgroundGradientOf(BuildContext context) =>
      paletteOf(context).backgroundGradient;
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
  static Color orbPrimaryOf(BuildContext context) =>
      paletteOf(context).orbPrimary;
  static Color orbAccentOf(BuildContext context) =>
      paletteOf(context).orbAccent;
}
