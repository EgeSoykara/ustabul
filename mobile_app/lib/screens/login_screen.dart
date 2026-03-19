import 'package:flutter/material.dart';

import '../config/brand_config.dart';
import '../state/session_controller.dart';
import '../widgets/brand_backdrop.dart';
import 'site_shell_screen.dart';

class LoginScreen extends StatefulWidget {
  const LoginScreen({
    super.key,
    required this.sessionController,
  });

  final SessionController sessionController;

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
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(message)));
    }
  }

  Future<void> _openSignupFlow({
    required String path,
    required String pageTitle,
  }) async {
    await Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (_) => SiteShellScreen.relativePath(
          path,
          pageTitle: pageTitle,
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: BrandBackdrop(
        child: SafeArea(
          child: Center(
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(24),
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 440),
                child: AnimatedBuilder(
                  animation: widget.sessionController,
                  builder: (context, _) {
                    return Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        Container(
                          padding: const EdgeInsets.all(24),
                          decoration: BrandConfig.heroPanelDecorationOf(
                            context,
                            radius: 30,
                          ),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Icon(
                                Icons.home_repair_service_rounded,
                                color: BrandConfig.accentOf(context),
                                size: 36,
                              ),
                              const SizedBox(height: 18),
                              Text(
                                'UstaBul Mobil',
                                style: TextStyle(
                                  color: BrandConfig.textOf(context),
                                  fontSize: 28,
                                  fontWeight: FontWeight.w800,
                                ),
                              ),
                              const SizedBox(height: 8),
                              Text(
                                'Usta bulma, talep açma ve iş takibini webdeki premium deneyime yakın bir akışla sunar.',
                                style: TextStyle(
                                  color: BrandConfig.heroTextMutedOf(context),
                                  height: 1.45,
                                ),
                              ),
                              const SizedBox(height: 18),
                              Wrap(
                                spacing: 10,
                                runSpacing: 10,
                                children: const [
                                  _HeroTag(
                                    icon: Icons.person_search_rounded,
                                    label: 'Usta bul',
                                  ),
                                  _HeroTag(
                                    icon: Icons.receipt_long_rounded,
                                    label: 'Talep oluştur',
                                  ),
                                  _HeroTag(
                                    icon: Icons.handshake_outlined,
                                    label: 'Anlaşmaları yönet',
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
                                      prefixIcon: Icon(
                                        Icons.person_outline_rounded,
                                      ),
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
                                      prefixIcon: Icon(
                                        Icons.lock_outline_rounded,
                                      ),
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
                                    onPressed:
                                        widget.sessionController.isLoading
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
                                  const SizedBox(height: 18),
                                  Container(
                                    padding: const EdgeInsets.all(16),
                                    decoration:
                                        BrandConfig.glassPanelDecorationOf(
                                      context,
                                      radius: 24,
                                    ),
                                    child: Column(
                                      crossAxisAlignment:
                                          CrossAxisAlignment.start,
                                      children: [
                                        Text(
                                          'Hesabın yok mu?',
                                          style: Theme.of(context)
                                              .textTheme
                                              .titleMedium
                                              ?.copyWith(
                                                fontWeight: FontWeight.w800,
                                              ),
                                        ),
                                        const SizedBox(height: 6),
                                        Text(
                                          'Kayıt akışı sitedeki doğrulama adımlarıyla uyumlu şekilde uygulama içinde açılır.',
                                          style: TextStyle(
                                            color: BrandConfig.textMutedOf(
                                              context,
                                            ),
                                            height: 1.4,
                                          ),
                                        ),
                                        const SizedBox(height: 14),
                                        Row(
                                          children: [
                                            Expanded(
                                              child: OutlinedButton.icon(
                                                onPressed: () =>
                                                    _openSignupFlow(
                                                  path: '/musteri/kayit/',
                                                  pageTitle: 'Müşteri Kaydı',
                                                ),
                                                icon: const Icon(
                                                  Icons
                                                      .person_add_alt_1_rounded,
                                                ),
                                                label: const Text(
                                                  'Müşteri kaydı',
                                                ),
                                              ),
                                            ),
                                            const SizedBox(width: 10),
                                            Expanded(
                                              child: FilledButton.tonalIcon(
                                                onPressed: () =>
                                                    _openSignupFlow(
                                                  path: '/usta/kayit/',
                                                  pageTitle: 'Usta Kaydı',
                                                ),
                                                icon: const Icon(
                                                  Icons.engineering_rounded,
                                                ),
                                                label: const Text(
                                                  'Usta kaydı',
                                                ),
                                              ),
                                            ),
                                          ],
                                        ),
                                      ],
                                    ),
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
      ),
    );
  }
}

class _HeroTag extends StatelessWidget {
  const _HeroTag({
    required this.icon,
    required this.label,
  });

  final IconData icon;
  final String label;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        color: BrandConfig.surfaceAltOf(context).withValues(alpha: 0.72),
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: BrandConfig.borderOf(context)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 18, color: BrandConfig.accentOf(context)),
          const SizedBox(width: 8),
          Text(
            label,
            style: TextStyle(
              color: BrandConfig.textOf(context),
              fontWeight: FontWeight.w700,
            ),
          ),
        ],
      ),
    );
  }
}
