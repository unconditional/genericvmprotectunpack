#pragma once

#include <string>
#include <vector>
#include <Windows.h>
#include <string>
#include <sstream>
#include <cstring>
#include <iomanip>
#include <cstdint>
#include <type_traits>

inline std::string ToHex(uintptr_t addr)
{
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setw(sizeof(uintptr_t) * 2) << std::setfill('0') << addr;
    return oss.str();
}

namespace Utils
{

    inline DWORD Align(DWORD value, DWORD alignment)
    {
        return (value + alignment - 1) & ~(alignment - 1);
    }

    inline DWORD PtrToRVA(BYTE *base, BYTE *ptr)
    {
        return static_cast<DWORD>(ptr - base);
    }

    inline bool ReadFileToBuffer(const std::string &filepath, std::vector<BYTE> &outBuffer)
    {
        HANDLE hFile = CreateFileA(filepath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                                   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
            return false;

        DWORD fileSize = GetFileSize(hFile, NULL);
        if (fileSize == INVALID_FILE_SIZE || fileSize == 0)
        {
            CloseHandle(hFile);
            return false;
        }

        outBuffer.resize(fileSize);
        DWORD bytesRead = 0;
        bool result = ReadFile(hFile, outBuffer.data(), fileSize, &bytesRead, NULL);
        CloseHandle(hFile);
        return result && bytesRead == fileSize;
    }

    inline bool WriteBufferToFile(const std::string &filepath, const BYTE *data, DWORD size)
    {
        HANDLE hFile = CreateFileA(filepath.c_str(), GENERIC_WRITE, 0, NULL,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
            return false;

        DWORD bytesWritten = 0;
        bool result = WriteFile(hFile, data, size, &bytesWritten, NULL);
        CloseHandle(hFile);
        return result && bytesWritten == size;
    }

    inline std::string ToHex(DWORD val)
    {
        char buf[16];
        sprintf_s(buf, "0x%08X", val);
        return std::string(buf);
    }

    inline std::string GetSectionName(PIMAGE_SECTION_HEADER section)
    {
        char name[9] = {0};
        memcpy(name, section->Name, 8);
        return std::string(name);
    }

    inline std::string FormatImpl(const char *fmt)
    {
        return std::string(fmt);
    }

    template <typename T>
    void WriteFormatValue(std::ostringstream &oss, char specifier, T value)
    {
        using ValueType = std::remove_cv_t<std::remove_reference_t<T>>;

        switch (specifier)
        {
        case 's':
            if constexpr (std::is_convertible_v<T, const char *>)
            {
                const char *text = value;
                oss << (text != nullptr ? text : "(null)");
            }
            else
            {
                oss << value;
            }
            break;

        case 'd':
        case 'i':
            if constexpr (std::is_enum_v<ValueType>)
            {
                using UnderlyingType = std::underlying_type_t<ValueType>;
                oss << static_cast<long long>(
                    static_cast<UnderlyingType>(value));
            }
            else if constexpr (std::is_arithmetic_v<ValueType>)
            {
                oss << static_cast<long long>(value);
            }
            else
            {
                oss << value;
            }
            break;

        case 'u':
            if constexpr (std::is_enum_v<ValueType>)
            {
                using UnderlyingType = std::underlying_type_t<ValueType>;
                oss << static_cast<unsigned long long>(
                    static_cast<UnderlyingType>(value));
            }
            else if constexpr (std::is_arithmetic_v<ValueType>)
            {
                oss << static_cast<unsigned long long>(value);
            }
            else
            {
                oss << value;
            }
            break;

        case 'x':
        case 'X':
            if (specifier == 'X')
                oss << std::uppercase;

            oss << std::hex;

            if constexpr (std::is_enum_v<ValueType>)
            {
                using UnderlyingType = std::underlying_type_t<ValueType>;
                oss << static_cast<unsigned long long>(
                    static_cast<UnderlyingType>(value));
            }
            else if constexpr (std::is_arithmetic_v<ValueType>)
            {
                oss << static_cast<unsigned long long>(value);
            }
            else if constexpr (std::is_pointer_v<ValueType>)
            {
                oss << reinterpret_cast<std::uintptr_t>(value);
            }
            else
            {
                oss << value;
            }

            oss << std::dec << std::nouppercase;
            break;

        case 'p':
            if constexpr (std::is_pointer_v<ValueType>)
            {
                oss << "0x" << std::hex
                    << reinterpret_cast<std::uintptr_t>(value)
                    << std::dec;
            }
            else if constexpr (std::is_enum_v<ValueType>)
            {
                using UnderlyingType = std::underlying_type_t<ValueType>;
                oss << "0x" << std::hex
                    << static_cast<unsigned long long>(
                           static_cast<UnderlyingType>(value))
                    << std::dec;
            }
            else if constexpr (std::is_integral_v<ValueType>)
            {
                oss << "0x" << std::hex
                    << static_cast<unsigned long long>(value)
                    << std::dec;
            }
            else
            {
                oss << value;
            }
            break;

        case 'f':
            if constexpr (std::is_floating_point_v<ValueType>)
            {
                oss << std::fixed << std::setprecision(6) << value;
            }
            else if constexpr (std::is_arithmetic_v<ValueType>)
            {
                oss << std::fixed << std::setprecision(6) << static_cast<double>(value);
            }
            else
            {
                oss << value;
            }
            break;

        default:
            oss << value;
            break;
        }
    }

    template <typename T, typename... Args>
    std::string FormatImpl(const char *fmt, T value, Args... args)
    {
        std::ostringstream oss;

        while (*fmt)
        {
            if (*fmt == '%' && *(fmt + 1) != '\0')
            {
                const char specifier = *(fmt + 1);

                if (specifier == 's' ||
                    specifier == 'd' ||
                    specifier == 'i' ||
                    specifier == 'u' ||
                    specifier == 'x' ||
                    specifier == 'X' ||
                    specifier == 'p' ||
                    specifier == 'f')
                {
                    WriteFormatValue(oss, specifier, value);

                    fmt += 2;
                    oss << FormatImpl(fmt, args...);
                    return oss.str();
                }
            }

            oss << *fmt++;
        }

        return oss.str();
    }

    template <typename... Args>
    static std::string Format(const char *fmt, Args... args)
    {
        return FormatImpl(fmt, args...);
    }

}
