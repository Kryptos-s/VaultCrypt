#include "MainWindow.h"
#include <QApplication>
#include <QSettings>
#include <QStyleFactory>

int main(int argc, char* argv[])
{
    QApplication app(argc, argv);

    // Set application info for QSettings
    QCoreApplication::setOrganizationName("VaultCrypt");
    QCoreApplication::setApplicationName("VaultCrypt");

    // Enable high DPI support
    app.setAttribute(Qt::AA_EnableHighDpiScaling);
    app.setAttribute(Qt::AA_UseHighDpiPixmaps);

    // Set default font
    QFont font("Segoe UI", 10);
    app.setFont(font);

    // Create and show main window
    MainWindow window;
    window.show();

    return app.exec();
}