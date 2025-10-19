#pragma once
#include "Theme.hpp"
#include <QObject>
#include <QPalette>

namespace vaultcrypt {

    class ThemeManager : public QObject {
        Q_OBJECT

    public:
        explicit ThemeManager(QObject* parent = nullptr);

        void applyTheme(const Theme& theme);
        Theme currentTheme() const { return m_currentTheme; }

        QString generateStylesheet(const Theme& theme);
        QPalette generatePalette(const Theme& theme);

    signals:
        void themeChanged(const Theme& theme);

    private:
        Theme m_currentTheme;

        QString replaceTokens(const QString& qss, const Theme& theme);
    };

} // namespace vaultcrypt