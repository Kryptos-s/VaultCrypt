#include "ThemeManager.hpp"
#include <QApplication>

namespace vaultcrypt {

    ThemeManager::ThemeManager(QObject* parent)
        : QObject(parent), m_currentTheme(Theme::Dark())
    {
    }

    void ThemeManager::applyTheme(const Theme& theme) {
        m_currentTheme = theme;

        // Apply stylesheet
        QString stylesheet = generateStylesheet(theme);
        qApp->setStyleSheet(stylesheet);

        // Apply palette
        QPalette palette = generatePalette(theme);
        qApp->setPalette(palette);

        emit themeChanged(theme);
    }

    QPalette ThemeManager::generatePalette(const Theme& theme) {
        QPalette palette;
        palette.setColor(QPalette::Window, theme.bg);
        palette.setColor(QPalette::WindowText, theme.fg);
        palette.setColor(QPalette::Base, theme.surface);
        palette.setColor(QPalette::AlternateBase, theme.surfaceHover);
        palette.setColor(QPalette::Text, theme.fg);
        palette.setColor(QPalette::Button, theme.surface);
        palette.setColor(QPalette::ButtonText, theme.fg);
        palette.setColor(QPalette::Highlight, theme.accent);
        palette.setColor(QPalette::HighlightedText, Qt::white);
        palette.setColor(QPalette::Link, theme.accent);
        return palette;
    }

    QString ThemeManager::generateStylesheet(const Theme& theme) {
        QString qss = R"(
        * {
            font-family: "Segoe UI", "Arial", sans-serif;
            font-size: 10pt;
        }
        
        QMainWindow, QWidget {
            background-color: @BG;
            color: @FG;
        }
        
        /* Sidebar */
        #sidebarFrame {
            background-color: @SURFACE;
            border-right: 1px solid @BORDER;
        }
        
        #logoLabel {
            font-size: 16pt;
            font-weight: 700;
            color: @FG;
            padding: 12px;
            background-color: transparent;
        }
        
        /* Navigation List */
        QListWidget {
            background-color: transparent;
            border: none;
            outline: none;
        }
        
        QListWidget::item {
            background-color: transparent;
            color: @FG;
            padding: 12px 16px;
            border-radius: 6px;
            margin: 2px 0px;
        }
        
        QListWidget::item:hover {
            background-color: @SURFACE_HOVER;
        }
        
        QListWidget::item:selected {
            background-color: @ACCENT;
            color: white;
            font-weight: 600;
        }
        
        QListWidget::item:focus {
            outline: 2px solid @ACCENT;
            outline-offset: 1px;
        }
        
        /* Group Boxes - NO BACKGROUND */
        QGroupBox {
            border: 1px solid @BORDER;
            border-radius: 8px;
            margin-top: 16px;
            padding-top: 24px;
            padding-left: 16px;
            padding-right: 16px;
            padding-bottom: 16px;
            background-color: transparent;
            font-weight: 600;
            font-size: 10pt;
            color: @FG;
        }
        
        QGroupBox::title {
            subcontrol-origin: margin;
            subcontrol-position: top left;
            padding: 0px 8px;
            color: @FG;
            background-color: transparent;
        }
        
        /* Labels - NO BACKGROUND */
        QLabel {
            color: @FG;
            background-color: transparent;
        }
        
        QLabel[heading="1"] {
            font-size: 28pt;
            font-weight: 700;
            color: @FG;
            background-color: transparent;
        }
        
        QLabel[heading="2"] {
            font-size: 14pt;
            font-weight: 600;
            color: @FG;
            background-color: transparent;
        }
        
        /* Buttons */
        QPushButton {
            background-color: @ACCENT;
            color: white;
            border: none;
            border-radius: 6px;
            padding: 10px 20px;
            font-weight: 600;
            min-height: 36px;
        }
        
        QPushButton:hover {
            background-color: @ACCENT_HOVER;
        }
        
        QPushButton:pressed {
            background-color: @ACCENT_PRESSED;
        }
        
        QPushButton:focus {
            outline: 2px solid @ACCENT;
            outline-offset: 2px;
        }
        
        QPushButton#secondaryButton {
            background-color: transparent;
            color: @FG;
            border: 1px solid @BORDER;
        }
        
        QPushButton#secondaryButton:hover {
            background-color: @SURFACE_HOVER;
            border-color: @ACCENT;
        }
        
        /* Input Fields */
        QLineEdit, QSpinBox, QComboBox {
            background-color: @SURFACE;
            color: @FG;
            border: 1px solid @BORDER;
            border-radius: 6px;
            padding: 10px 12px;
            min-height: 20px;
            selection-background-color: @ACCENT;
            selection-color: white;
        }
        
        QLineEdit:focus, QSpinBox:focus, QComboBox:focus {
            border: 2px solid @ACCENT;
            outline: none;
        }
        
        /* ComboBox */
        QComboBox::drop-down {
            border: none;
            width: 30px;
        }
        
        QComboBox::down-arrow {
            image: none;
            border-left: 5px solid transparent;
            border-right: 5px solid transparent;
            border-top: 6px solid @FG;
            margin-right: 8px;
        }
        
        QComboBox QAbstractItemView {
            background-color: @SURFACE;
            color: @FG;
            border: 1px solid @BORDER;
            selection-background-color: @ACCENT;
            selection-color: white;
            padding: 4px;
        }
        
        /* Text Edit */
        QTextEdit {
            background-color: @SURFACE;
            color: @FG;
            border: 1px solid @BORDER;
            border-radius: 6px;
            padding: 8px;
            selection-background-color: @ACCENT;
            selection-color: white;
        }
        
        QTextEdit:focus {
            border: 2px solid @ACCENT;
        }
        
        /* Status Bar */
        QStatusBar {
            background-color: @ACCENT;
            color: white;
            font-weight: 600;
            padding: 8px;
            border: none;
        }
        
        QStatusBar::item {
            border: none;
        }
        
        QStatusBar QLabel {
            color: white;
            background-color: transparent;
        }
        
        /* Menu Bar */
        QMenuBar {
            background-color: @SURFACE;
            color: @FG;
            border-bottom: 1px solid @BORDER;
            padding: 4px;
        }
        
        QMenuBar::item {
            background-color: transparent;
            padding: 6px 12px;
            border-radius: 4px;
        }
        
        QMenuBar::item:selected {
            background-color: @ACCENT;
            color: white;
        }
        
        QMenu {
            background-color: @SURFACE;
            color: @FG;
            border: 1px solid @BORDER;
            padding: 4px;
        }
        
        QMenu::item {
            padding: 8px 24px;
            border-radius: 4px;
            background-color: transparent;
        }
        
        QMenu::item:selected {
            background-color: @ACCENT;
            color: white;
        }
        
        /* Scrollbar */
        QScrollBar:vertical {
            background-color: @BG;
            width: 12px;
            border: none;
        }
        
        QScrollBar::handle:vertical {
            background-color: @BORDER;
            border-radius: 6px;
            min-height: 30px;
        }
        
        QScrollBar::handle:vertical:hover {
            background-color: @ACCENT;
        }
        
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            height: 0px;
        }
        
        /* Progress Bar */
        QProgressBar {
            background-color: @SURFACE;
            border: 1px solid @BORDER;
            border-radius: 6px;
            text-align: center;
            color: @FG;
            height: 24px;
        }
        
        QProgressBar::chunk {
            background-color: @ACCENT;
            border-radius: 4px;
        }
    )";

        return replaceTokens(qss, theme);
    }

    QString ThemeManager::replaceTokens(const QString& qss, const Theme& theme) {
        QString result = qss;
        result.replace("@BG", theme.bg.name());
        result.replace("@FG", theme.fg.name());
        result.replace("@SURFACE", theme.surface.name());
        result.replace("@BORDER", theme.border.name());
        result.replace("@ACCENT", theme.accent.name());
        result.replace("@ACCENT_HOVER", theme.accentHover.name());
        result.replace("@ACCENT_PRESSED", theme.accentPressed.name());
        result.replace("@SURFACE_HOVER", theme.surfaceHover.name());
        result.replace("@SUCCESS", theme.success.name());
        result.replace("@WARNING", theme.warning.name());
        result.replace("@DANGER", theme.danger.name());
        return result;
    }

} // namespace vaultcrypt