import 'package:flutter/material.dart';

import '../config/brand_config.dart';

class BrandBackdrop extends StatelessWidget {
  const BrandBackdrop({
    super.key,
    required this.child,
  });

  final Widget child;

  @override
  Widget build(BuildContext context) {
    final primaryOrb = BrandConfig.orbPrimaryOf(context).withValues(alpha: 0.8);
    final accentOrb = BrandConfig.orbAccentOf(context).withValues(alpha: 0.78);
    return DecoratedBox(
      decoration: BrandConfig.backgroundDecorationOf(context),
      child: Stack(
        fit: StackFit.expand,
        children: [
          IgnorePointer(
            child: Stack(
              children: [
                _GlowOrb(
                  alignment: const Alignment(-1.04, -0.92),
                  size: 180,
                  color: primaryOrb,
                ),
                _GlowOrb(
                  alignment: const Alignment(1.02, 0.88),
                  size: 164,
                  color: accentOrb,
                ),
                _GlowOrb(
                  alignment: const Alignment(0.82, -0.34),
                  size: 92,
                  color: primaryOrb.withValues(alpha: 0.38),
                ),
              ],
            ),
          ),
          child,
        ],
      ),
    );
  }
}

class _GlowOrb extends StatelessWidget {
  const _GlowOrb({
    required this.alignment,
    required this.size,
    required this.color,
  });

  final Alignment alignment;
  final double size;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Align(
      alignment: alignment,
      child: Container(
        width: size,
        height: size,
        decoration: BoxDecoration(
          shape: BoxShape.circle,
          boxShadow: [
            BoxShadow(
              color: color,
              blurRadius: size * 0.5,
              spreadRadius: size * 0.03,
            ),
          ],
        ),
      ),
    );
  }
}
