#pragma once

#include <string>
#include <fstream>
#include <mutex>

namespace vaultcrypt {

    enum class LogLevel {
        Debug = 0,
        Info = 1,
        Warning = 2,
        Error = 3,
        Critical = 4
    };

    class Logger {
    public:
        static Logger& instance();

        void set_level(LogLevel level);
        void set_file(const std::string& path);

        void log(LogLevel level, const std::string& message);
        void debug(const std::string& message);
        void info(const std::string& message);
        void warning(const std::string& message);
        void error(const std::string& message);
        void critical(const std::string& message);

    private:
        Logger();
        ~Logger();

        LogLevel level_{ LogLevel::Error };
        std::ofstream file_;
        std::mutex mutex_;
    };

#define LOG_DEBUG(msg) vaultcrypt::Logger::instance().debug(msg)
#define LOG_INFO(msg) vaultcrypt::Logger::instance().info(msg)
#define LOG_WARNING(msg) vaultcrypt::Logger::instance().warning(msg)
#define LOG_ERROR(msg) vaultcrypt::Logger::instance().error(msg)
#define LOG_CRITICAL(msg) vaultcrypt::Logger::instance().critical(msg)

} // namespace vaultcrypt
