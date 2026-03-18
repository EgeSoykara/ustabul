class AppConfig {
  static const _defaultSiteUrl = 'https://ustabul.onrender.com';
  static const _siteUrlFromEnv =
      String.fromEnvironment('SITE_URL', defaultValue: '');
  static const userAgent = 'UstaBulMobile/1.0';

  // Override with:
  // flutter run --dart-define=SITE_URL=https://ustabul.onrender.com
  // Local dev example:
  // flutter run --dart-define=SITE_URL=http://10.0.2.2:8000
  static String get siteUrl {
    if (_siteUrlFromEnv.isNotEmpty) {
      return _siteUrlFromEnv;
    }
    return _defaultSiteUrl;
  }

  static String get apiBaseUrl => siteUrl;

  static Uri get siteUri => Uri.parse(siteUrl);
}
