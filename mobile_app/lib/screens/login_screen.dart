import 'package:flutter/material.dart';

import '../config/brand_config.dart';
import '../services/theme_storage.dart';
import '../state/session_controller.dart';
import '../state/theme_controller.dart';

class LoginScreen extends StatefulWidget {
  const LoginScreen({
    super.key,
    required this.sessionController,
    required this.themeController,
  });

  final SessionController sessionController;
  final ThemeController themeController;

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  final _formKey = GlobalKey<FormState>();
  final _usernameController = TextEditingController();
  final _passwordController = TextEditingController();

  @override
  void dispose() {
    _usernameController.dispose();
    _passwordController.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (!_formKey.currentState!.validate()) {
      return;
    }
    final ok = await widget.sessionController.login(
      username: _usernameController.text.trim(),
      password: _passwordController.text,
    );
    if (!mounted) {
      return;
    }
    if (!ok) {
      final message = widget.sessionController.error ?? 'Giriş başarısız.';
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text(message)));
    }
  }

  Future<void> _setTheme(AppThemePreference preference) async {
    await widget.themeController.setPreference(preference);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 420),
              child: AnimatedBuilder(
                animation: Listenable.merge([
                  widget.sessionController,
                  widget.themeController,
                ]),
                builder: (context, _) {
                  return Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      Container(
                        padding: const EdgeInsets.all(24),
                        decoration: BoxDecoration(
                          borderRadius: BorderRadius.circular(30),
                          gradient: BrandConfig.heroGradientOf(context),
                        ),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Icon(
                              Icons.home_repair_service_rounded,
                              color: BrandConfig.text,
                              size: 36,
                            ),
                            const SizedBox(height: 18),
                            const Text(
                              'UstaBul Mobil',
                              style: TextStyle(
                                color: BrandConfig.text,
                                fontSize: 28,
                                fontWeight: FontWeight.w800,
                              ),
                            ),
                            const SizedBox(height: 8),
                            Text(
                              'Müşteri ve usta deneyimini uygulama odaklı bir akışla sunar.',
                              style: TextStyle(
                                color: BrandConfig.heroTextMutedOf(context),
                                height: 1.45,
                              ),
                            ),
                            const SizedBox(height: 18),
                            Wrap(
                              spacing: 10,
                              runSpacing: 10,
                              children: [
                                ChoiceChip(
                                  label: const Text('Karanlık mod'),
                                  selected: widget.themeController.preference ==
                                      AppThemePreference.dark,
                                  labelStyle: TextStyle(
                                    color: widget.themeController.preference ==
                                            AppThemePreference.dark
                                        ? BrandConfig.text
                                        : BrandConfig.heroTextMutedOf(context),
                                    fontWeight: FontWeight.w700,
                                  ),
                                  side: BorderSide(
                                    color: BrandConfig.heroTextMutedOf(context)
                                        .withValues(alpha: 0.35),
                                  ),
                                  selectedColor: Colors.white.withValues(
                                    alpha: 0.16,
                                  ),
                                  backgroundColor: Colors.white.withValues(
                                    alpha: 0.08,
                                  ),
                                  onSelected: (_) =>
                                      _setTheme(AppThemePreference.dark),
                                ),
                                ChoiceChip(
                                  label: const Text('Aydınlık mod'),
                                  selected: widget.themeController.preference ==
                                      AppThemePreference.light,
                                  labelStyle: TextStyle(
                                    color: widget.themeController.preference ==
                                            AppThemePreference.light
                                        ? BrandConfig.text
                                        : BrandConfig.heroTextMutedOf(context),
                                    fontWeight: FontWeight.w700,
                                  ),
                                  side: BorderSide(
                                    color: BrandConfig.heroTextMutedOf(context)
                                        .withValues(alpha: 0.35),
                                  ),
                                  selectedColor: Colors.white.withValues(
                                    alpha: 0.16,
                                  ),
                                  backgroundColor: Colors.white.withValues(
                                    alpha: 0.08,
                                  ),
                                  onSelected: (_) =>
                                      _setTheme(AppThemePreference.light),
                                ),
                              ],
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(height: 18),
                      Card(
                        child: Padding(
                          padding: const EdgeInsets.all(20),
                          child: Form(
                            key: _formKey,
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.stretch,
                              children: [
                                Text(
                                  'Hesabınıza giriş yapın',
                                  style: Theme.of(context)
                                      .textTheme
                                      .titleLarge
                                      ?.copyWith(
                                        fontWeight: FontWeight.w800,
                                      ),
                                ),
                                const SizedBox(height: 8),
                                Text(
                                  'Müşteri veya usta hesabınızla devam edin.',
                                  style: TextStyle(
                                    color: BrandConfig.textMutedOf(context),
                                  ),
                                ),
                                const SizedBox(height: 20),
                                TextFormField(
                                  controller: _usernameController,
                                  decoration: const InputDecoration(
                                    labelText: 'Kullanıcı adı',
                                    prefixIcon:
                                        Icon(Icons.person_outline_rounded),
                                  ),
                                  validator: (value) {
                                    if ((value ?? '').trim().isEmpty) {
                                      return 'Kullanıcı adı gerekli.';
                                    }
                                    return null;
                                  },
                                ),
                                const SizedBox(height: 12),
                                TextFormField(
                                  controller: _passwordController,
                                  obscureText: true,
                                  decoration: const InputDecoration(
                                    labelText: 'Şifre',
                                    prefixIcon:
                                        Icon(Icons.lock_outline_rounded),
                                  ),
                                  validator: (value) {
                                    if ((value ?? '').isEmpty) {
                                      return 'Şifre gerekli.';
                                    }
                                    return null;
                                  },
                                ),
                                const SizedBox(height: 18),
                                FilledButton(
                                  onPressed: widget.sessionController.isLoading
                                      ? null
                                      : _submit,
                                  style: FilledButton.styleFrom(
                                    minimumSize: const Size.fromHeight(54),
                                  ),
                                  child: widget.sessionController.isLoading
                                      ? const SizedBox(
                                          width: 18,
                                          height: 18,
                                          child: CircularProgressIndicator(
                                            strokeWidth: 2,
                                          ),
                                        )
                                      : const Text('Giriş yap'),
                                ),
                              ],
                            ),
                          ),
                        ),
                      ),
                      const SizedBox(height: 14),
                      Text(
                        'Destek: ustabulcyprus@gmail.com',
                        textAlign: TextAlign.center,
                        style: TextStyle(
                          color: BrandConfig.textMutedOf(context),
                        ),
                      ),
                    ],
                  );
                },
              ),
            ),
          ),
        ),
      ),
    );
  }
}
