#include "vaultcrypt/logger.h"
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace vaultcrypt {

    Logger& Logger::instance() {
        static Logger instance;
        return instance;
    }

    Logger::Logger() = default;

    Logger::~Logger() {
        if (file_.is_open()) {
            file_.close();
        }
    }

    void Logger::set_level(LogLevel level) {
        std::lock_guard<std::mutex> lock(mutex_);
        level_ = level;
    }

    void Logger::set_file(const std::string& path) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (file_.is_open()) {
            file_.close();
        }
        file_.open(path, std::ios::app);
    }

    void Logger::log(LogLevel level, const std::string& message) {
        if (level < level_) return;

        std::lock_guard<std::mutex> lock(mutex_);

        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);

        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");

        const char* level_str[] = { "DEBUG", "INFO", "WARN", "ERROR", "CRIT" };
        std::string log_line = ss.str() + " [" + level_str[static_cast<int>(level)] + "] " + message + "\n";

        if (file_.is_open()) {
            file_ << log_line;
            file_.flush();
        }
        else {
            std::cerr << log_line;
        }
    }

    void Logger::debug(const std::string& message) { log(LogLevel::Debug, message); }
    void Logger::info(const std::string& message) { log(LogLevel::Info, message); }
    void Logger::warning(const std::string& message) { log(LogLevel::Warning, message); }
    void Logger::error(const std::string& message) { log(LogLevel::Error, message); }
    void Logger::critical(const std::string& message) { log(LogLevel::Critical, message); }

} // namespace vaultcrypt