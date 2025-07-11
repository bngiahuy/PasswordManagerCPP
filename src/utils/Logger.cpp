#include "Logger.h"

void Logger::error(const std::string &message) {
    std::cerr << "[ERROR] " << message << std::endl;
}

void Logger::warning(const std::string &message) {
    std::cerr << "[WARNING] " << message << std::endl;
}

void Logger::info(const std::string &message) {
    std::cout << "[INFO] " << message << std::endl;
}

void Logger::debug(const std::string &message) {
    std::cout << "[DEBUG] " << message << std::endl;
}