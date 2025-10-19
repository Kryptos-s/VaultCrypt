#pragma once
#include <QString>
#include <QColor>

namespace vaultcrypt {

    struct Theme {
        QString name;
        QColor bg;
        QColor fg;
        QColor surface;
        QColor border;
        QColor accent;
        QColor success;
        QColor warning;
        QColor danger;

        // Derived colors
        QColor accentHover;
        QColor accentPressed;
        QColor surfaceHover;

        Theme() = default;

        void computeDerived() {
            accentHover = accent.lighter(110);
            accentPressed = accent.darker(110);
            surfaceHover = surface.lighter(105);
        }

        static Theme Light() {
            Theme t;
            t.name = "Light";
            t.bg = QColor("#f6f7fb");
            t.fg = QColor("#1a1c1e");
            t.surface = QColor("#ffffff");
            t.border = QColor("#dfe3eb");
            t.accent = QColor("#3b82f6");
            t.success = QColor("#16a34a");
            t.warning = QColor("#f59e0b");
            t.danger = QColor("#dc2626");
            t.computeDerived();
            return t;
        }

        static Theme Dark() {
            Theme t;
            t.name = "Dark";
            t.bg = QColor("#0f1115");
            t.fg = QColor("#e6e8eb");
            t.surface = QColor("#191b22");
            t.border = QColor("#2a2f3a");
            t.accent = QColor("#7c93ff");
            t.success = QColor("#22c55e");
            t.warning = QColor("#fbbf24");
            t.danger = QColor("#f87171");
            t.computeDerived();
            return t;
        }

        static Theme Midnight() {
            Theme t;
            t.name = "Midnight";
            t.bg = QColor("#0a0c10");
            t.fg = QColor("#d7dae0");
            t.surface = QColor("#12151b");
            t.border = QColor("#1d2230");
            t.accent = QColor("#8b5cf6");
            t.success = QColor("#10b981");
            t.warning = QColor("#f59e0b");
            t.danger = QColor("#ef4444");
            t.computeDerived();
            return t;
        }
    };

} // namespace vaultcrypt