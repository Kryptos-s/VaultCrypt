#pragma once

#include <QMainWindow>
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QGroupBox>
#include <QLabel>
#include <QPushButton>
#include <QLineEdit>
#include <QTextEdit>
#include <QComboBox>
#include <QSpinBox>
#include <QCheckBox>
#include <QListWidget>
#include <QStackedWidget>
#include <QFrame>
#include <QMenuBar>
#include <QMenu>
#include <QAction>
#include <QStatusBar>
#include <QToolBar>
#include <QSettings>
#include <QPropertyAnimation>
#include <memory>

#include "theme/ThemeManager.hpp"

namespace vaultcrypt {
    class Keystore;
}

class EncryptPage;
class DecryptPage;
class KeyManagerPage;
class SettingsPage;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget* parent = nullptr);
    ~MainWindow();

private slots:
    void onNavigationChanged(int index);
    void onThemeChanged(const vaultcrypt::Theme& theme);

private:
    void setupUi();
    void setupMenuBar();
    void setupToolBar();
    void setupSidebar();
    void setupPages();
    void loadSettings();
    void saveSettings();

    void animatePageTransition(int fromIndex, int toIndex);

    // Theme
    vaultcrypt::ThemeManager* themeManager;

    // Main Layout
    QFrame* sidebarFrame;
    QListWidget* navigationList;
    QStackedWidget* stackedWidget;
    QLabel* logoLabel;
    QLabel* statusLabel;

    // Pages
    EncryptPage* encryptPage;
    DecryptPage* decryptPage;
    KeyManagerPage* keyManagerPage;
    SettingsPage* settingsPage;

    // Settings
    QSettings* settings;
};

// Page Base Class
class BasePage : public QWidget {
    Q_OBJECT
public:
    explicit BasePage(QWidget* parent = nullptr) : QWidget(parent) {}
    virtual ~BasePage() = default;
};

// Encrypt Page
class EncryptPage : public BasePage {
    Q_OBJECT
public:
    explicit EncryptPage(QWidget* parent = nullptr);

private slots:
    void onEncryptClicked();
    void onInputBrowse();
    void onOutputBrowse();

private:
    void setupUi();

    QLineEdit* inputFileEdit;
    QLineEdit* outputFileEdit;
    QLineEdit* passwordEdit;
    QComboBox* algorithmCombo;
    QComboBox* kdfCombo;
    QSpinBox* iterationsSpinBox;
    QSpinBox* memorySpinBox;
    QPushButton* encryptButton;
    QTextEdit* logTextEdit;

    void appendLog(const QString& message);
    void showError(const QString& message);
};

// Decrypt Page
class DecryptPage : public BasePage {
    Q_OBJECT
public:
    explicit DecryptPage(QWidget* parent = nullptr);

private slots:
    void onDecryptClicked();
    void onInputBrowse();
    void onOutputBrowse();

private:
    void setupUi();

    QLineEdit* inputFileEdit;
    QLineEdit* outputFileEdit;
    QLineEdit* passwordEdit;
    QComboBox* algorithmCombo;
    QPushButton* decryptButton;
    QTextEdit* logTextEdit;

    void appendLog(const QString& message);
    void showError(const QString& message);
};

// Key Manager Page
class KeyManagerPage : public BasePage {
    Q_OBJECT
public:
    explicit KeyManagerPage(QWidget* parent = nullptr);

private slots:
    void onGenerateKey();
    void onImportKey();
    void onExportKey();
    void onSecureDelete();

private:
    void setupUi();

    QPushButton* generateKeyButton;
    QPushButton* importKeyButton;
    QPushButton* exportKeyButton;
    QPushButton* secureDeleteButton;
    QTextEdit* logTextEdit;

    void appendLog(const QString& message);
};

// Settings Page
class SettingsPage : public BasePage {
    Q_OBJECT
public:
    explicit SettingsPage(QWidget* parent = nullptr);

    void setThemeManager(vaultcrypt::ThemeManager* manager);

signals:
    void themeChangeRequested(const QString& themeName);
    void accentChangeRequested(const QColor& color);

private slots:
    void onThemeSelected(int index);
    void onAccentSelected();

private:
    void setupUi();

    QComboBox* themeCombo;
    QFrame* accentFrame;
    QCheckBox* systemThemeCheckBox;

    vaultcrypt::ThemeManager* themeManager;

    void createAccentButtons();
};