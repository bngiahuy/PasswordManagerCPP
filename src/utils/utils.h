#pragma once
#include <string>
#include <sstream>
#include <iomanip>

class Utils
{
public:
    // Helper function: Convert a string to its hexadecimal representation
    static std::string toHex(const std::string &input);

    // Helper function: Convert a hexadecimal string back to binary
    static std::string fromHex(const std::string &hex);
};