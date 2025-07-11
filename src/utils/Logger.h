#pragma once

#include <iostream>

class Logger {

public:
    Logger() = delete; // Prevent instantiation

    // Log an error message
    static void error(const std::string &message);

    // Log a warning message
    static void warning(const std::string &message);

    // Log an info message
    static void info(const std::string &message);

    // Log a debug message
    static void debug(const std::string &message);
};