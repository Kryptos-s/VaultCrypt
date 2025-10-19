#include "MainWindow.h"
#include "vaultcrypt/aead.h"
#include "vaultcrypt/file_io.h"
#include "vaultcrypt/error.h"
#include "vaultcrypt/version.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QProgressDialog>
#include <QDateTime>
#include <QPropertyAnimation>
#include <QGraphicsOpacityEffect>
#include <QFileInfo>
#include <QInputDialog>
#include <chrono>

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
{
    setWindowTitle("VaultCrypt - Professional Encryption Suite");
    setMinimumSize(900, 650); // ADD THIS - prevents window from getting too small
    resize(1200, 800);

    // Initialize theme manager
    themeManager = new vaultcrypt::ThemeManager(this);

    // Initialize settings
    settings = new QSettings("VaultCrypt", "VaultCrypt", this);

    setupUi();
    setupMenuBar();
    setupToolBar();

    loadSettings();

    // Connect theme changes
    connect(themeManager, &vaultcrypt::ThemeManager::themeChanged,
        this, &MainWindow::onThemeChanged);
}

MainWindow::~MainWindow() {
    saveSettings();
}

void MainWindow::setupUi() {
    // Central widget
    QWidget* centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);

    QHBoxLayout* mainLayout = new QHBoxLayout(centralWidget);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(0);

    setupSidebar();
    mainLayout->addWidget(sidebarFrame);

    // Content area
    QFrame* contentFrame = new QFrame();
    contentFrame->setFrameShape(QFrame::NoFrame);
    QVBoxLayout* contentLayout = new QVBoxLayout(contentFrame);
    contentLayout->setContentsMargins(0, 0, 0, 0);
    contentLayout->setSpacing(0);

    stackedWidget = new QStackedWidget();
    contentLayout->addWidget(stackedWidget);

    mainLayout->addWidget(contentFrame, 1);

    setupPages();

    // Status bar
    statusLabel = new QLabel("Ready");
    statusLabel->setStyleSheet("font-weight: 600; padding: 2px 8px;");
    statusBar()->addWidget(statusLabel);
}

void MainWindow::setupSidebar() {
    sidebarFrame = new QFrame();
    sidebarFrame->setObjectName("sidebarFrame");
    sidebarFrame->setMinimumWidth(220);
    sidebarFrame->setMaximumWidth(220);

    QVBoxLayout* sidebarLayout = new QVBoxLayout(sidebarFrame);
    sidebarLayout->setContentsMargins(12, 20, 12, 20);
    sidebarLayout->setSpacing(8);

    // Logo
    logoLabel = new QLabel("VAULTCRYPT");
    logoLabel->setObjectName("logoLabel");
    logoLabel->setAlignment(Qt::AlignCenter);
    sidebarLayout->addWidget(logoLabel);

    sidebarLayout->addSpacing(20);

    // Navigation list
    navigationList = new QListWidget();
    navigationList->setFocusPolicy(Qt::StrongFocus);
    navigationList->setFrameShape(QFrame::NoFrame);
    navigationList->setIconSize(QSize(24, 24));
    navigationList->setSpacing(4);

    navigationList->addItem("Encrypt");
    navigationList->addItem("Decrypt");
    navigationList->addItem("Key Manager");
    navigationList->addItem("Settings");

    navigationList->setCurrentRow(0);

    connect(navigationList, &QListWidget::currentRowChanged,
        this, &MainWindow::onNavigationChanged);

    sidebarLayout->addWidget(navigationList);
    sidebarLayout->addStretch();

    // Version label
    QLabel* versionLabel = new QLabel("v" VAULTCRYPT_VERSION);
    versionLabel->setStyleSheet("color: #888; font-size: 9pt;");
    versionLabel->setAlignment(Qt::AlignCenter);
    sidebarLayout->addWidget(versionLabel);
}

void MainWindow::setupPages() {
    encryptPage = new EncryptPage();
    decryptPage = new DecryptPage();
    keyManagerPage = new KeyManagerPage();
    settingsPage = new SettingsPage();

    settingsPage->setThemeManager(themeManager);

    stackedWidget->addWidget(encryptPage);
    stackedWidget->addWidget(decryptPage);
    stackedWidget->addWidget(keyManagerPage);
    stackedWidget->addWidget(settingsPage);

    // Connect settings page theme change
    connect(settingsPage, &SettingsPage::themeChangeRequested,
        [this](const QString& themeName) {
            vaultcrypt::Theme theme;
            if (themeName == "Light") theme = vaultcrypt::Theme::Light();
            else if (themeName == "Dark") theme = vaultcrypt::Theme::Dark();
            else if (themeName == "Midnight") theme = vaultcrypt::Theme::Midnight();
            themeManager->applyTheme(theme);
        });
}

void MainWindow::setupMenuBar() {
    QMenuBar* menuBar = new QMenuBar(this);
    setMenuBar(menuBar);

    // File Menu
    QMenu* fileMenu = menuBar->addMenu("File");
    QAction* exitAction = fileMenu->addAction("Exit");
    exitAction->setShortcut(QKeySequence::Quit);
    connect(exitAction, &QAction::triggered, this, &QMainWindow::close);

    // Tools Menu
    QMenu* toolsMenu = menuBar->addMenu("Tools");
    QAction* batchAction = toolsMenu->addAction("Batch Encrypt");
    QAction* benchmarkAction = toolsMenu->addAction("Benchmark");

    // View Menu
    QMenu* viewMenu = menuBar->addMenu("View");
    QMenu* themeMenu = viewMenu->addMenu("Theme");

    QAction* lightAction = themeMenu->addAction("Light");
    QAction* darkAction = themeMenu->addAction("Dark");
    QAction* midnightAction = themeMenu->addAction("Midnight");

    connect(lightAction, &QAction::triggered, [this]() {
        themeManager->applyTheme(vaultcrypt::Theme::Light());
        });
    connect(darkAction, &QAction::triggered, [this]() {
        themeManager->applyTheme(vaultcrypt::Theme::Dark());
        });
    connect(midnightAction, &QAction::triggered, [this]() {
        themeManager->applyTheme(vaultcrypt::Theme::Midnight());
        });

    // Help Menu
    QMenu* helpMenu = menuBar->addMenu("Help");
    QAction* aboutAction = helpMenu->addAction("About");
    connect(aboutAction, &QAction::triggered, [this]() {
        QString aboutText = QString(
            "<h2>VaultCrypt v%1</h2>"
            "<p><b>Professional Encryption Suite</b></p>"
            "<hr>"
            "<p><b>Features:</b></p>"
            "<ul>"
            "<li>AES-256-GCM encryption</li>"
            "<li>XChaCha20-Poly1305 encryption</li>"
            "<li>Argon2id key derivation</li>"
            "<li>Professional theming system</li>"
            "</ul>"
            "<p>&copy; 2025 VaultCrypt Project</p>"
        ).arg(VAULTCRYPT_VERSION);
        QMessageBox::about(this, "About VaultCrypt", aboutText);
        });
}

void MainWindow::setupToolBar() {
    QToolBar* toolBar = addToolBar("Main Toolbar");
    toolBar->setMovable(false);
    toolBar->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);

    // Add some common actions
    QAction* newAction = toolBar->addAction("New");
    QAction* openAction = toolBar->addAction("Open");

    toolBar->addSeparator();
}

void MainWindow::onNavigationChanged(int index) {
    int currentIndex = stackedWidget->currentIndex();
    if (currentIndex != index) {
        animatePageTransition(currentIndex, index);
    }
}

void MainWindow::animatePageTransition(int fromIndex, int toIndex) {
    // Simple fade transition
    QWidget* currentPage = stackedWidget->widget(fromIndex);
    QWidget* nextPage = stackedWidget->widget(toIndex);

    if (!currentPage || !nextPage) {
        stackedWidget->setCurrentIndex(toIndex);
        return;
    }

    QGraphicsOpacityEffect* fadeOut = new QGraphicsOpacityEffect(currentPage);
    currentPage->setGraphicsEffect(fadeOut);

    QPropertyAnimation* animation = new QPropertyAnimation(fadeOut, "opacity");
    animation->setDuration(100);
    animation->setStartValue(1.0);
    animation->setEndValue(0.0);

    connect(animation, &QPropertyAnimation::finished, [this, toIndex, currentPage]() {
        currentPage->setGraphicsEffect(nullptr);
        stackedWidget->setCurrentIndex(toIndex);
        });

    animation->start(QPropertyAnimation::DeleteWhenStopped);
}

void MainWindow::onThemeChanged(const vaultcrypt::Theme& theme) {
    statusLabel->setText("Theme: " + theme.name);
}

void MainWindow::loadSettings() {
    // Load last theme
    QString themeName = settings->value("theme", "Dark").toString();

    vaultcrypt::Theme theme;
    if (themeName == "Light") theme = vaultcrypt::Theme::Light();
    else if (themeName == "Midnight") theme = vaultcrypt::Theme::Midnight();
    else theme = vaultcrypt::Theme::Dark();

    themeManager->applyTheme(theme);

    // Load last page
    int lastPage = settings->value("lastPage", 0).toInt();
    if (lastPage >= 0 && lastPage < stackedWidget->count()) {
        navigationList->setCurrentRow(lastPage);
        stackedWidget->setCurrentIndex(lastPage);
    }

    // Load window geometry
    restoreGeometry(settings->value("geometry").toByteArray());
    restoreState(settings->value("windowState").toByteArray());
}

void MainWindow::saveSettings() {
    settings->setValue("theme", themeManager->currentTheme().name);
    settings->setValue("lastPage", stackedWidget->currentIndex());
    settings->setValue("geometry", saveGeometry());
    settings->setValue("windowState", saveState());
}
// EncryptPage Implementation
EncryptPage::EncryptPage(QWidget* parent) : BasePage(parent) {
    setupUi();
}
void EncryptPage::setupUi() {
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(24, 24, 24, 24);
    mainLayout->setSpacing(16);

    // Title
    QLabel* titleLabel = new QLabel("Encrypt Files");
    titleLabel->setProperty("heading", "1");
    mainLayout->addWidget(titleLabel);

    // File Selection
    QGroupBox* fileGroup = new QGroupBox("File Selection");
    QVBoxLayout* fileLayout = new QVBoxLayout(fileGroup);
    fileLayout->setSpacing(10);

    QWidget* inputWidget = new QWidget();
    QHBoxLayout* inputLayout = new QHBoxLayout(inputWidget);
    inputLayout->setContentsMargins(0, 0, 0, 0);
    inputLayout->setSpacing(10);
    QLabel* inputLabel = new QLabel("Input:");
    inputLabel->setMinimumWidth(60);
    inputLabel->setMaximumWidth(60);
    inputFileEdit = new QLineEdit();
    inputFileEdit->setPlaceholderText("Select file...");
    QPushButton* inputBtn = new QPushButton("Browse");
    inputBtn->setObjectName("secondaryButton");
    inputBtn->setMaximumWidth(90);
    connect(inputBtn, &QPushButton::clicked, this, &EncryptPage::onInputBrowse);
    inputLayout->addWidget(inputLabel);
    inputLayout->addWidget(inputFileEdit, 1);
    inputLayout->addWidget(inputBtn);
    fileLayout->addWidget(inputWidget);

    QWidget* outputWidget = new QWidget();
    QHBoxLayout* outputLayout = new QHBoxLayout(outputWidget);
    outputLayout->setContentsMargins(0, 0, 0, 0);
    outputLayout->setSpacing(10);
    QLabel* outputLabel = new QLabel("Output:");
    outputLabel->setMinimumWidth(60);
    outputLabel->setMaximumWidth(60);
    outputFileEdit = new QLineEdit();
    outputFileEdit->setPlaceholderText("Auto-generated...");
    QPushButton* outputBtn = new QPushButton("Browse");
    outputBtn->setObjectName("secondaryButton");
    outputBtn->setMaximumWidth(90);
    connect(outputBtn, &QPushButton::clicked, this, &EncryptPage::onOutputBrowse);
    outputLayout->addWidget(outputLabel);
    outputLayout->addWidget(outputFileEdit, 1);
    outputLayout->addWidget(outputBtn);
    fileLayout->addWidget(outputWidget);

    mainLayout->addWidget(fileGroup);

    // Crypto Settings
    QGroupBox* cryptoGroup = new QGroupBox("Encryption Settings");
    QVBoxLayout* cryptoLayout = new QVBoxLayout(cryptoGroup);
    cryptoLayout->setSpacing(10);

    // Algorithm
    QWidget* algWidget = new QWidget();
    QHBoxLayout* algLayout = new QHBoxLayout(algWidget);
    algLayout->setContentsMargins(0, 0, 0, 0);
    QLabel* algLabel = new QLabel("Algorithm:");
    algLabel->setMinimumWidth(100);
    algorithmCombo = new QComboBox();
    algorithmCombo->addItem("AES-256-GCM");
    algorithmCombo->addItem("XChaCha20-Poly1305");
    algLayout->addWidget(algLabel);
    algLayout->addWidget(algorithmCombo, 1);
    cryptoLayout->addWidget(algWidget);

    // Password
    QWidget* pwdWidget = new QWidget();
    QHBoxLayout* pwdLayout = new QHBoxLayout(pwdWidget);
    pwdLayout->setContentsMargins(0, 0, 0, 0);
    QLabel* pwdLabel = new QLabel("Password:");
    pwdLabel->setMinimumWidth(100);
    passwordEdit = new QLineEdit();
    passwordEdit->setEchoMode(QLineEdit::Password);
    passwordEdit->setPlaceholderText("Enter password...");
    pwdLayout->addWidget(pwdLabel);
    pwdLayout->addWidget(passwordEdit, 1);
    cryptoLayout->addWidget(pwdWidget);

    // KDF
    QWidget* kdfWidget = new QWidget();
    QHBoxLayout* kdfLayout = new QHBoxLayout(kdfWidget);
    kdfLayout->setContentsMargins(0, 0, 0, 0);
    QLabel* kdfLabel = new QLabel("KDF:");
    kdfLabel->setMinimumWidth(100);
    kdfCombo = new QComboBox();
    kdfCombo->addItem("Argon2id");
    kdfCombo->addItem("PBKDF2-SHA256");
    kdfLayout->addWidget(kdfLabel);
    kdfLayout->addWidget(kdfCombo, 1);
    cryptoLayout->addWidget(kdfWidget);

    // Iterations & Memory side by side
    QWidget* paramsWidget = new QWidget();
    QHBoxLayout* paramsLayout = new QHBoxLayout(paramsWidget);
    paramsLayout->setContentsMargins(0, 0, 0, 0);

    QLabel* iterLabel = new QLabel("Iterations:");
    iterationsSpinBox = new QSpinBox();
    iterationsSpinBox->setRange(1, 100);
    iterationsSpinBox->setValue(3);

    QLabel* memLabel = new QLabel("Memory:");
    memorySpinBox = new QSpinBox();
    memorySpinBox->setRange(8192, 1048576);
    memorySpinBox->setValue(65536);
    memorySpinBox->setSuffix(" KB");

    paramsLayout->addWidget(iterLabel);
    paramsLayout->addWidget(iterationsSpinBox, 1);
    paramsLayout->addSpacing(20);
    paramsLayout->addWidget(memLabel);
    paramsLayout->addWidget(memorySpinBox, 1);
    cryptoLayout->addWidget(paramsWidget);

    mainLayout->addWidget(cryptoGroup);

    // Button
    QHBoxLayout* btnLayout = new QHBoxLayout();
    btnLayout->addStretch();
    encryptButton = new QPushButton("ENCRYPT");
    encryptButton->setMinimumSize(120, 40);
    encryptButton->setMaximumWidth(200);
    encryptButton->setCursor(Qt::PointingHandCursor);
    connect(encryptButton, &QPushButton::clicked, this, &EncryptPage::onEncryptClicked);
    btnLayout->addWidget(encryptButton);
    mainLayout->addLayout(btnLayout);

    // Log
    QLabel* logLabel = new QLabel("Activity Log");
    logLabel->setProperty("heading", "2");
    mainLayout->addWidget(logLabel);

    logTextEdit = new QTextEdit();
    logTextEdit->setReadOnly(true);
    logTextEdit->setFont(QFont("Consolas", 9));
    mainLayout->addWidget(logTextEdit, 1); // Stretch factor makes it grow

    appendLog("Ready to encrypt files");
}
void EncryptPage::onInputBrowse() {
    QString fileName = QFileDialog::getOpenFileName(this,
        "Select Input File", QString(), "All Files (*.*)");
    if (!fileName.isEmpty()) {
        inputFileEdit->setText(fileName);
        appendLog("Selected: " + QFileInfo(fileName).fileName());
    }
}

void EncryptPage::onOutputBrowse() {
    QString fileName = QFileDialog::getSaveFileName(this,
        "Select Output File", QString(), "Encrypted Files (*.enc);;All Files (*.*)");
    if (!fileName.isEmpty()) {
        outputFileEdit->setText(fileName);
    }
}

void EncryptPage::onEncryptClicked() {
    try {
        QString inputPath = inputFileEdit->text();
        QString outputPath = outputFileEdit->text();
        QString password = passwordEdit->text();

        if (inputPath.isEmpty()) {
            showError("Please select an input file");
            return;
        }

        if (password.isEmpty()) {
            showError("Please enter a password");
            return;
        }

        if (outputPath.isEmpty()) {
            outputPath = inputPath + ".enc";
            outputFileEdit->setText(outputPath);
        }

        QProgressDialog progress("Encrypting file...", "Cancel", 0, 100, this);
        progress.setWindowModality(Qt::WindowModal);
        progress.setMinimumDuration(0);
        progress.setValue(30);

        appendLog("Reading: " + QFileInfo(inputPath).fileName());
        vaultcrypt::SecureBytes plaintext = vaultcrypt::read_file(inputPath.toStdString());
        appendLog(QString("Read %1 bytes").arg(plaintext.size()));

        std::string pwd_str = password.toStdString();
        vaultcrypt::SecureString pass(pwd_str.begin(), pwd_str.end());

        vaultcrypt::KDFParams kdf_params;
        kdf_params.type = kdfCombo->currentIndex() == 0 ?
            vaultcrypt::KDFType::Argon2id : vaultcrypt::KDFType::PBKDF2_SHA256;
        kdf_params.iterations = iterationsSpinBox->value();
        kdf_params.memory_kb = memorySpinBox->value();
        kdf_params.parallelism = 4;

        progress.setValue(50);

        appendLog("Encrypting with " + algorithmCombo->currentText() + "...");

        vaultcrypt::SecureBytes ciphertext;
        auto startTime = std::chrono::high_resolution_clock::now();

        if (algorithmCombo->currentIndex() == 0) {
            vaultcrypt::AESGCMCipher cipher;
            ciphertext = cipher.encrypt_password(pass, plaintext, kdf_params);
        }
        else {
            vaultcrypt::ChaCha20Poly1305Cipher cipher;
            ciphertext = cipher.encrypt_password(pass, plaintext, kdf_params);
        }

        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

        progress.setValue(80);

        appendLog("Writing encrypted file...");
        vaultcrypt::write_file(outputPath.toStdString(), ciphertext, true);

        progress.setValue(100);

        QString msg = QString("Encryption successful!\n\n"
            "Original: %1 bytes\n"
            "Encrypted: %2 bytes\n"
            "Time: %3 ms")
            .arg(plaintext.size())
            .arg(ciphertext.size())
            .arg(duration.count());

        appendLog(QString("SUCCESS: Encrypted in %1 ms").arg(duration.count()));

        QMessageBox::information(this, "Encryption Complete", msg);

    }
    catch (const vaultcrypt::VaultCryptException& e) {
        showError(QString("Encryption failed: ") + e.what());
    }
    catch (const std::exception& e) {
        showError(QString("Error: ") + e.what());
    }
}

void EncryptPage::appendLog(const QString& message) {
    QString timestamp = QDateTime::currentDateTime().toString("hh:mm:ss");
    logTextEdit->append(QString("[%1] %2").arg(timestamp, message));
}

void EncryptPage::showError(const QString& message) {
    appendLog("ERROR: " + message);
    QMessageBox::critical(this, "Error", message);
}

// DecryptPage Implementation
DecryptPage::DecryptPage(QWidget* parent) : BasePage(parent) {
    setupUi();
}

void DecryptPage::setupUi() {
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(32, 32, 32, 32);
    mainLayout->setSpacing(20);

    // Title
    QLabel* titleLabel = new QLabel("Decrypt Files");
    titleLabel->setProperty("heading", "1");
    mainLayout->addWidget(titleLabel);

    // File Selection Group
    QGroupBox* fileGroup = new QGroupBox("File Selection");
    QVBoxLayout* fileGroupLayout = new QVBoxLayout(fileGroup);
    fileGroupLayout->setSpacing(12);

    // Input file row
    QHBoxLayout* inputLayout = new QHBoxLayout();
    QLabel* inputLabel = new QLabel("Input File:");
    inputLabel->setMinimumWidth(100);
    inputFileEdit = new QLineEdit();
    inputFileEdit->setPlaceholderText("Select encrypted file...");
    inputFileEdit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    QPushButton* inputBrowseBtn = new QPushButton("Browse");
    inputBrowseBtn->setObjectName("secondaryButton");
    inputBrowseBtn->setFixedWidth(100);
    connect(inputBrowseBtn, &QPushButton::clicked, this, &DecryptPage::onInputBrowse);
    inputLayout->addWidget(inputLabel);
    inputLayout->addWidget(inputFileEdit, 1);
    inputLayout->addWidget(inputBrowseBtn);
    fileGroupLayout->addLayout(inputLayout);

    // Output file row
    QHBoxLayout* outputLayout = new QHBoxLayout();
    QLabel* outputLabel = new QLabel("Output File:");
    outputLabel->setMinimumWidth(100);
    outputFileEdit = new QLineEdit();
    outputFileEdit->setPlaceholderText("Auto-generated if empty...");
    outputFileEdit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    QPushButton* outputBrowseBtn = new QPushButton("Browse");
    outputBrowseBtn->setObjectName("secondaryButton");
    outputBrowseBtn->setFixedWidth(100);
    connect(outputBrowseBtn, &QPushButton::clicked, this, &DecryptPage::onOutputBrowse);
    outputLayout->addWidget(outputLabel);
    outputLayout->addWidget(outputFileEdit, 1);
    outputLayout->addWidget(outputBrowseBtn);
    fileGroupLayout->addLayout(outputLayout);

    mainLayout->addWidget(fileGroup);

    // Decryption Settings Group
    QGroupBox* cryptoGroup = new QGroupBox("Decryption Settings");
    QVBoxLayout* cryptoGroupLayout = new QVBoxLayout(cryptoGroup);
    cryptoGroupLayout->setSpacing(12);

    // Algorithm row
    QHBoxLayout* algLayout = new QHBoxLayout();
    QLabel* algLabel = new QLabel("Algorithm:");
    algLabel->setMinimumWidth(100);
    algorithmCombo = new QComboBox();
    algorithmCombo->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    algorithmCombo->addItem("AES-256-GCM");
    algorithmCombo->addItem("XChaCha20-Poly1305");
    algLayout->addWidget(algLabel);
    algLayout->addWidget(algorithmCombo, 1);
    cryptoGroupLayout->addLayout(algLayout);

    // Password row
    QHBoxLayout* pwdLayout = new QHBoxLayout();
    QLabel* pwdLabel = new QLabel("Password:");
    pwdLabel->setMinimumWidth(100);
    passwordEdit = new QLineEdit();
    passwordEdit->setEchoMode(QLineEdit::Password);
    passwordEdit->setPlaceholderText("Enter password...");
    passwordEdit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    pwdLayout->addWidget(pwdLabel);
    pwdLayout->addWidget(passwordEdit, 1);
    cryptoGroupLayout->addLayout(pwdLayout);

    mainLayout->addWidget(cryptoGroup);

    // Button
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();
    decryptButton = new QPushButton("DECRYPT");
    decryptButton->setMinimumSize(140, 44);
    decryptButton->setCursor(Qt::PointingHandCursor);
    connect(decryptButton, &QPushButton::clicked, this, &DecryptPage::onDecryptClicked);
    buttonLayout->addWidget(decryptButton);
    mainLayout->addLayout(buttonLayout);

    // Log
    QLabel* logLabel = new QLabel("Activity Log");
    logLabel->setProperty("heading", "2");
    mainLayout->addWidget(logLabel);

    logTextEdit = new QTextEdit();
    logTextEdit->setReadOnly(true);
    logTextEdit->setMinimumHeight(100);
    logTextEdit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    logTextEdit->setFont(QFont("Consolas", 9));
    mainLayout->addWidget(logTextEdit);

    appendLog("Ready to decrypt files");
}

void DecryptPage::onInputBrowse() {
    QString fileName = QFileDialog::getOpenFileName(this,
        "Select Encrypted File", QString(), "Encrypted Files (*.enc);;All Files (*.*)");
    if (!fileName.isEmpty()) {
        inputFileEdit->setText(fileName);
        appendLog("Selected: " + QFileInfo(fileName).fileName());
    }
}

void DecryptPage::onOutputBrowse() {
    QString fileName = QFileDialog::getSaveFileName(this,
        "Select Output File", QString(), "All Files (*.*)");
    if (!fileName.isEmpty()) {
        outputFileEdit->setText(fileName);
    }
}

void DecryptPage::onDecryptClicked() {
    try {
        QString inputPath = inputFileEdit->text();
        QString outputPath = outputFileEdit->text();
        QString password = passwordEdit->text();

        if (inputPath.isEmpty()) {
            showError("Please select an input file");
            return;
        }

        if (password.isEmpty()) {
            showError("Please enter a password");
            return;
        }

        if (outputPath.isEmpty()) {
            if (inputPath.endsWith(".enc")) {
                outputPath = inputPath.left(inputPath.length() - 4);
            }
            else {
                outputPath = inputPath + ".dec";
            }
            outputFileEdit->setText(outputPath);
        }

        QProgressDialog progress("Decrypting file...", "Cancel", 0, 100, this);
        progress.setWindowModality(Qt::WindowModal);
        progress.setMinimumDuration(0);
        progress.setValue(30);

        appendLog("Reading: " + QFileInfo(inputPath).fileName());
        vaultcrypt::SecureBytes ciphertext = vaultcrypt::read_file(inputPath.toStdString());
        appendLog(QString("Read %1 bytes").arg(ciphertext.size()));

        std::string pwd_str = password.toStdString();
        vaultcrypt::SecureString pass(pwd_str.begin(), pwd_str.end());

        progress.setValue(50);

        vaultcrypt::SecureBytes plaintext;
        auto startTime = std::chrono::high_resolution_clock::now();

        appendLog("Decrypting...");

        if (algorithmCombo->currentIndex() == 0) {
            vaultcrypt::AESGCMCipher cipher;
            plaintext = cipher.decrypt_password(pass, ciphertext);
        }
        else {
            vaultcrypt::ChaCha20Poly1305Cipher cipher;
            plaintext = cipher.decrypt_password(pass, ciphertext);
        }

        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

        if (plaintext.empty()) {
            throw vaultcrypt::VaultCryptException(vaultcrypt::ErrorCode::DecryptionFailed,
                "Decryption produced empty result");
        }

        progress.setValue(80);

        appendLog("Writing decrypted file...");
        vaultcrypt::write_file(outputPath.toStdString(), plaintext, true);

        progress.setValue(100);

        QString msg = QString("Decryption successful!\n\n"
            "Encrypted: %1 bytes\n"
            "Decrypted: %2 bytes\n"
            "Time: %3 ms")
            .arg(ciphertext.size())
            .arg(plaintext.size())
            .arg(duration.count());

        appendLog(QString("SUCCESS: Decrypted in %1 ms").arg(duration.count()));

        QMessageBox::information(this, "Decryption Complete", msg);

    }
    catch (const vaultcrypt::VaultCryptException& e) {
        showError(QString("Decryption failed: ") + e.what());
    }
    catch (const std::exception& e) {
        showError(QString("Error: ") + e.what());
    }
}

void DecryptPage::appendLog(const QString& message) {
    QString timestamp = QDateTime::currentDateTime().toString("hh:mm:ss");
    logTextEdit->append(QString("[%1] %2").arg(timestamp, message));
}

void DecryptPage::showError(const QString& message) {
    appendLog("ERROR: " + message);
    QMessageBox::critical(this, "Error", message);
}


// KeyManagerPage Implementation
KeyManagerPage::KeyManagerPage(QWidget* parent) : BasePage(parent) {
    setupUi();
}

void KeyManagerPage::setupUi() {
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(32, 32, 32, 32);
    mainLayout->setSpacing(20);

    // Title
    QLabel* titleLabel = new QLabel("Key Manager");
    titleLabel->setProperty("heading", "1");
    mainLayout->addWidget(titleLabel);

    QLabel* descLabel = new QLabel("Manage encryption keys and perform security operations");
    descLabel->setStyleSheet("color: #888; font-size: 11pt;");
    mainLayout->addWidget(descLabel);

    mainLayout->addSpacing(10);

    // Key Operations Group
    QGroupBox* keyOpsGroup = new QGroupBox("Key Operations");
    QVBoxLayout* keyOpsLayout = new QVBoxLayout(keyOpsGroup);
    keyOpsLayout->setSpacing(10);

    generateKeyButton = new QPushButton("Generate New Key");
    generateKeyButton->setMinimumHeight(44);
    generateKeyButton->setCursor(Qt::PointingHandCursor);
    connect(generateKeyButton, &QPushButton::clicked, this, &KeyManagerPage::onGenerateKey);
    keyOpsLayout->addWidget(generateKeyButton);

    importKeyButton = new QPushButton("Import Key");
    importKeyButton->setObjectName("secondaryButton");
    importKeyButton->setMinimumHeight(44);
    importKeyButton->setCursor(Qt::PointingHandCursor);
    connect(importKeyButton, &QPushButton::clicked, this, &KeyManagerPage::onImportKey);
    keyOpsLayout->addWidget(importKeyButton);

    exportKeyButton = new QPushButton("Export Key");
    exportKeyButton->setObjectName("secondaryButton");
    exportKeyButton->setMinimumHeight(44);
    exportKeyButton->setCursor(Qt::PointingHandCursor);
    connect(exportKeyButton, &QPushButton::clicked, this, &KeyManagerPage::onExportKey);
    keyOpsLayout->addWidget(exportKeyButton);

    mainLayout->addWidget(keyOpsGroup);

    // Security Tools Group
    QGroupBox* securityGroup = new QGroupBox("Security Tools");
    QVBoxLayout* securityLayout = new QVBoxLayout(securityGroup);
    securityLayout->setSpacing(10);

    secureDeleteButton = new QPushButton("Secure File Deletion");
    secureDeleteButton->setMinimumHeight(44);
    secureDeleteButton->setCursor(Qt::PointingHandCursor);
    secureDeleteButton->setStyleSheet("QPushButton { background-color: #dc2626; } QPushButton:hover { background-color: #b91c1c; }");
    connect(secureDeleteButton, &QPushButton::clicked, this, &KeyManagerPage::onSecureDelete);
    securityLayout->addWidget(secureDeleteButton);

    mainLayout->addWidget(securityGroup);

    // Log
    QLabel* logLabel = new QLabel("Activity Log");
    logLabel->setProperty("heading", "2");
    mainLayout->addWidget(logLabel);

    logTextEdit = new QTextEdit();
    logTextEdit->setReadOnly(true);
    logTextEdit->setMinimumHeight(100);
    logTextEdit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    logTextEdit->setFont(QFont("Consolas", 9));
    mainLayout->addWidget(logTextEdit);

    mainLayout->addStretch();

    appendLog("Key Manager ready");
}

void KeyManagerPage::onGenerateKey() {
    QString fileName = QFileDialog::getSaveFileName(this,
        "Save Key File", "", "Key Files (*.key);;All Files (*.*)");

    if (!fileName.isEmpty()) {
        try {
            vaultcrypt::SecureBytes key = vaultcrypt::generate_random(32);
            vaultcrypt::write_file(fileName.toStdString(), key, true);
            appendLog("Generated 256-bit key: " + QFileInfo(fileName).fileName());
            QMessageBox::information(this, "Success",
                "Generated and saved 256-bit encryption key.\n\n"
                "WARNING: Keep this key safe and secure!");
        }
        catch (const std::exception& e) {
            appendLog("ERROR: " + QString(e.what()));
            QMessageBox::critical(this, "Error", QString("Key generation failed: ") + e.what());
        }
    }
}

void KeyManagerPage::onImportKey() {
    QString fileName = QFileDialog::getOpenFileName(this,
        "Import Key File", "", "Key Files (*.key);;All Files (*.*)");

    if (!fileName.isEmpty()) {
        try {
            vaultcrypt::SecureBytes key = vaultcrypt::read_file(fileName.toStdString());
            appendLog(QString("Imported key: %1 (%2 bytes)")
                .arg(QFileInfo(fileName).fileName())
                .arg(key.size()));
            QMessageBox::information(this, "Success",
                QString("Successfully imported key.\n\nKey size: %1 bits").arg(key.size() * 8));
        }
        catch (const std::exception& e) {
            appendLog("ERROR: " + QString(e.what()));
            QMessageBox::critical(this, "Error", QString("Key import failed: ") + e.what());
        }
    }
}

void KeyManagerPage::onExportKey() {
    QMessageBox::information(this, "Export Key",
        "This feature allows you to export keys from the keystore.\n\n"
        "Implementation: Export selected key to file.");
    appendLog("Export key requested (not yet implemented)");
}

void KeyManagerPage::onSecureDelete() {
    QString fileName = QFileDialog::getOpenFileName(this,
        "Select File to Securely Delete", QString(), "All Files (*.*)");

    if (fileName.isEmpty()) return;

    auto reply = QMessageBox::warning(this, "Secure Delete",
        "WARNING: This will permanently delete the file!\n\n"
        "File: " + fileName + "\n\n"
        "This action CANNOT be undone. Continue?",
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);

    if (reply == QMessageBox::Yes) {
        try {
            vaultcrypt::SecureBytes fileData = vaultcrypt::read_file(fileName.toStdString());
            size_t fileSize = fileData.size();

            QProgressDialog progress("Securely deleting file...", QString(), 0, 3, this);
            progress.setWindowModality(Qt::WindowModal);
            progress.setMinimumDuration(0);

            // Overwrite 3 times
            for (int pass = 0; pass < 3; ++pass) {
                vaultcrypt::SecureBytes random = vaultcrypt::generate_random(fileSize);
                vaultcrypt::write_file(fileName.toStdString(), random, true);
                progress.setValue(pass + 1);
            }

            QFile::remove(fileName);

            appendLog("Securely deleted: " + QFileInfo(fileName).fileName());
            QMessageBox::information(this, "Success", "File securely deleted!");

        }
        catch (const std::exception& e) {
            appendLog("ERROR: " + QString(e.what()));
            QMessageBox::critical(this, "Error", QString("Secure deletion failed: ") + e.what());
        }
    }
}

void KeyManagerPage::appendLog(const QString& message) {
    QString timestamp = QDateTime::currentDateTime().toString("hh:mm:ss");
    logTextEdit->append(QString("[%1] %2").arg(timestamp, message));
}
// SettingsPage Implementation
SettingsPage::SettingsPage(QWidget* parent)
    : BasePage(parent), themeManager(nullptr) {
    setupUi();
}

void SettingsPage::setThemeManager(vaultcrypt::ThemeManager* manager) {
    themeManager = manager;
}
void SettingsPage::setupUi() {
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(32, 32, 32, 32);
    mainLayout->setSpacing(20);

    // Title
    QLabel* titleLabel = new QLabel("Settings");
    titleLabel->setProperty("heading", "1");
    mainLayout->addWidget(titleLabel);

    // Appearance Group
    QGroupBox* appearanceGroup = new QGroupBox("Appearance");
    QVBoxLayout* appearanceLayout = new QVBoxLayout(appearanceGroup);
    appearanceLayout->setSpacing(12);

    // Theme Selection row
    QHBoxLayout* themeLayout = new QHBoxLayout();
    QLabel* themeLabel = new QLabel("Theme:");
    themeLabel->setMinimumWidth(120);
    themeCombo = new QComboBox();
    themeCombo->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    themeCombo->addItem("Light");
    themeCombo->addItem("Dark");
    themeCombo->addItem("Midnight");
    themeCombo->setCurrentIndex(1);
    connect(themeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
        this, &SettingsPage::onThemeSelected);
    themeLayout->addWidget(themeLabel);
    themeLayout->addWidget(themeCombo, 1);
    appearanceLayout->addLayout(themeLayout);

    // System Theme Toggle
    systemThemeCheckBox = new QCheckBox("Use system theme");
    systemThemeCheckBox->setToolTip("Automatically switch between Light and Dark based on system settings");
    appearanceLayout->addWidget(systemThemeCheckBox);

    // Accent Color
    QLabel* accentLabel = new QLabel("Accent Color:");
    appearanceLayout->addWidget(accentLabel);

    accentFrame = new QFrame();
    QHBoxLayout* accentLayout = new QHBoxLayout(accentFrame);
    accentLayout->setSpacing(8);
    accentLayout->setContentsMargins(0, 0, 0, 0);
    createAccentButtons();
    appearanceLayout->addWidget(accentFrame);

    mainLayout->addWidget(appearanceGroup);

    // Application Group
    QGroupBox* appGroup = new QGroupBox("Application");
    QVBoxLayout* appLayout = new QVBoxLayout(appGroup);
    appLayout->setSpacing(12);

    QCheckBox* startupCheckBox = new QCheckBox("Launch on system startup");
    appLayout->addWidget(startupCheckBox);

    QCheckBox* notificationsCheckBox = new QCheckBox("Show notifications");
    notificationsCheckBox->setChecked(true);
    appLayout->addWidget(notificationsCheckBox);

    mainLayout->addWidget(appGroup);

    // Security Group
    QGroupBox* securityGroup = new QGroupBox("Security");
    QVBoxLayout* securityLayout = new QVBoxLayout(securityGroup);
    securityLayout->setSpacing(12);

    // Auto-lock timeout row
    QHBoxLayout* timeoutLayout = new QHBoxLayout();
    QLabel* timeoutLabel = new QLabel("Auto-lock timeout:");
    timeoutLabel->setMinimumWidth(120);
    QSpinBox* timeoutSpinBox = new QSpinBox();
    timeoutSpinBox->setRange(0, 60);
    timeoutSpinBox->setValue(5);
    timeoutSpinBox->setSuffix(" minutes");
    timeoutSpinBox->setSpecialValueText("Disabled");
    timeoutSpinBox->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    timeoutLayout->addWidget(timeoutLabel);
    timeoutLayout->addWidget(timeoutSpinBox, 1);
    securityLayout->addLayout(timeoutLayout);

    QCheckBox* clearClipboardCheckBox = new QCheckBox("Clear clipboard after copy");
    clearClipboardCheckBox->setChecked(true);
    securityLayout->addWidget(clearClipboardCheckBox);

    mainLayout->addWidget(securityGroup);

    // About Section
    mainLayout->addSpacing(10);

    QFrame* aboutFrame = new QFrame();
    aboutFrame->setStyleSheet("QFrame { border: 1px solid #444; border-radius: 8px; padding: 16px; }");
    QVBoxLayout* aboutLayout = new QVBoxLayout(aboutFrame);

    QLabel* aboutTitle = new QLabel("VaultCrypt v" VAULTCRYPT_VERSION);
    aboutTitle->setProperty("heading", "2");
    aboutLayout->addWidget(aboutTitle);

    QLabel* aboutDesc = new QLabel("Professional Encryption Suite");
    aboutDesc->setStyleSheet("color: #888;");
    aboutLayout->addWidget(aboutDesc);

    QLabel* aboutCopyright = new QLabel("© 2025 VaultCrypt Project");
    aboutCopyright->setStyleSheet("color: #888; font-size: 9pt;");
    aboutLayout->addWidget(aboutCopyright);

    mainLayout->addWidget(aboutFrame);

    mainLayout->addStretch();
}

void SettingsPage::createAccentButtons() {
    struct AccentColor {
        QString name;
        QColor color;
    };

    QList<AccentColor> accents = {
        {"Blue", QColor("#3b82f6")},
        {"Green", QColor("#10b981")},
        {"Purple", QColor("#8b5cf6")},
        {"Orange", QColor("#f59e0b")},
        {"Red", QColor("#ef4444")}
    };

    QHBoxLayout* layout = qobject_cast<QHBoxLayout*>(accentFrame->layout());

    for (const auto& accent : accents) {
        QPushButton* btn = new QPushButton();
        btn->setFixedSize(40, 40);
        btn->setStyleSheet(QString(
            "QPushButton {"
            "   background-color: %1;"
            "   border: 2px solid transparent;"
            "   border-radius: 20px;"
            "}"
            "QPushButton:hover {"
            "   border: 2px solid white;"
            "}"
            "QPushButton:pressed {"
            "   transform: scale(0.95);"
            "}"
        ).arg(accent.color.name()));
        btn->setCursor(Qt::PointingHandCursor);
        btn->setToolTip(accent.name);
        btn->setProperty("accentColor", accent.color);

        connect(btn, &QPushButton::clicked, this, &SettingsPage::onAccentSelected);

        layout->addWidget(btn);
    }

    layout->addStretch();
}

void SettingsPage::onThemeSelected(int index) {
    QString themeName;
    switch (index) {
    case 0: themeName = "Light"; break;
    case 1: themeName = "Dark"; break;
    case 2: themeName = "Midnight"; break;
    default: themeName = "Dark";
    }

    emit themeChangeRequested(themeName);
}

void SettingsPage::onAccentSelected() {
    QPushButton* btn = qobject_cast<QPushButton*>(sender());
    if (!btn) return;

    QColor accentColor = btn->property("accentColor").value<QColor>();

    if (themeManager) {
        vaultcrypt::Theme currentTheme = themeManager->currentTheme();
        currentTheme.accent = accentColor;
        currentTheme.computeDerived();
        themeManager->applyTheme(currentTheme);
    }

    emit accentChangeRequested(accentColor);
}