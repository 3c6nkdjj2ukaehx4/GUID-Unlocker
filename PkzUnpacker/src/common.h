#pragma once

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cwctype>
#include <filesystem>
#include <iterator>
#include <string>

namespace common
{

inline std::string Narrow(const std::wstring& text)
{
    if (text.empty())
        return {};

    const int length = WideCharToMultiByte(CP_UTF8, 0, text.data(),
                                           static_cast<int>(text.size()),
                                           nullptr, 0, nullptr, nullptr);
    if (length <= 0)
        return {};

    std::string result(static_cast<std::size_t>(length), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(),
                        static_cast<int>(text.size()), result.data(), length,
                        nullptr, nullptr);
    return result;
}

inline std::string Narrow(const std::filesystem::path& path)
{
    return Narrow(path.wstring());
}

inline std::wstring Lower(std::wstring text)
{
    std::transform(text.begin(), text.end(), text.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return text;
}

inline std::string Lower(std::string text)
{
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

inline bool IsPkzFile(const std::filesystem::path& path)
{
    return Lower(path.extension().wstring()) == L".pkz";
}

inline std::string HumanBytes(std::uint64_t bytes)
{
    static const char* units[] = { "B", "KiB", "MiB", "GiB", "TiB" };

    double value = static_cast<double>(bytes);
    std::size_t unit = 0;
    while (value >= 1024.0 && unit + 1 < std::size(units))
    {
        value /= 1024.0;
        ++unit;
    }

    char buffer[64] = {};
    if (unit == 0)
        std::snprintf(buffer, sizeof(buffer), "%llu B",
                      static_cast<unsigned long long>(bytes));
    else
        std::snprintf(buffer, sizeof(buffer), "%.2f %s", value, units[unit]);
    return buffer;
}

inline std::string Trim(const std::string& text)
{
    const std::size_t first = text.find_first_not_of(" \t\r\n");
    if (first == std::string::npos)
        return {};

    const std::size_t last = text.find_last_not_of(" \t\r\n");
    return text.substr(first, last - first + 1);
}

} // namespace common
