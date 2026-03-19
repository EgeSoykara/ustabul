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
    return DecoratedBox(
      decoration: BrandConfig.backgroundDecorationOf(context),
      child: Stack(
        fit: StackFit.expand,
        children: [
          IgnorePointer(
            child: Stack(
              children: [
                _GlowOrb(
                  alignment: const Alignment(-1.08, -0.96),
                  size: 220,
                  color: BrandConfig.orbPrimaryOf(context),
                ),
                _GlowOrb(
                  alignment: const Alignment(1.04, 0.82),
                  size: 200,
                  color: BrandConfig.orbAccentOf(context),
                ),
                _GlowOrb(
                  alignment: const Alignment(0.88, -0.4),
                  size: 120,
                  color: BrandConfig.orbPrimaryOf(context).withValues(
                    alpha: 0.55,
                  ),
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
              blurRadius: size * 0.65,
              spreadRadius: size * 0.08,
            ),
          ],
        ),
      ),
    );
  }
}
