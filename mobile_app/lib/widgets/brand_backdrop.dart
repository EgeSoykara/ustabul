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
    final primaryOrb = BrandConfig.orbPrimaryOf(context);
    final accentOrb = BrandConfig.orbAccentOf(context);
    return DecoratedBox(
      decoration: BrandConfig.backgroundDecorationOf(context),
      child: Stack(
        fit: StackFit.expand,
        children: [
          IgnorePointer(
            child: Stack(
              children: [
                _GlowOrb(
                  alignment: const Alignment(-0.92, -0.82),
                  size: 220,
                  color: primaryOrb,
                ),
                _GlowOrb(
                  alignment: const Alignment(0.96, 0.86),
                  size: 188,
                  color: accentOrb,
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
              blurRadius: size * 0.72,
              spreadRadius: size * 0.02,
            ),
          ],
        ),
      ),
    );
  }
}
