import 'package:flutter/material.dart';

import 'screens/site_shell_screen.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const UstaBulMobileApp());
}

class UstaBulMobileApp extends StatelessWidget {
  const UstaBulMobileApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'UstaBul Mobile',
      debugShowCheckedModeBanner: false,
      home: const SiteShellScreen(),
    );
  }
}
