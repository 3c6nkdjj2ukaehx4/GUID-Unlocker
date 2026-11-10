#include "pkz.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <exception>
#include <fstream>

extern "C"
{
#include "puff.h"
}

namespace pkz {
namespace {

constexpr std::uint32_t kEocdSignature = 0x06054B50;
constexpr std::uint32_t kCentralSignature = 0x02014B50;
constexpr std::uint32_t kLocalSignature = 0x04034B50;

// "LOCK": 62-byte trailer used by the current MX Bikes mod tools.
constexpr std::uint32_t kLockMagic = 0x4C4F434B;
// "LCK3": 56-byte trailer used by older tools.
constexpr std::uint32_t kLck3Magic = 0x4C434B33;

constexpr std::uint32_t kLockSizeKey = 0xAF1CC7FD;
constexpr std::uint16_t kLockChecksumKey = 0x7135;
constexpr std::uint32_t kLck3SizeKey = 0x8B1146F3;
constexpr std::uint16_t kLck3ChecksumKey = 0xB03B;

std::uint16_t ReadU16(const std::uint8_t* p)
{
    std::uint16_t value = 0;
    std::memcpy(&value, p, sizeof(value));
    return value;
}

std::uint32_t ReadU32(const std::uint8_t* p)
{
    std::uint32_t value = 0;
    std::memcpy(&value, p, sizeof(value));
    return value;
}

bool GetFileSize(FILE* file, std::uint64_t& size)
{
    if (_fseeki64(file, 0, SEEK_END) != 0)
        return false;

    const __int64 end = _ftelli64(file);
    if (end < 0)
        return false;

    size = static_cast<std::uint64_t>(end);
    return true;
}

bool ReadAt(FILE* file, std::uint64_t offset, void* destination, std::size_t length)
{
    if (_fseeki64(file, static_cast<__int64>(offset), SEEK_SET) != 0)
        return false;

    return length == 0 || std::fread(destination, 1, length, file) == length;
}

bool WriteAt(FILE* file, std::uint64_t offset, const void* source,
             std::size_t length)
{
    if (_fseeki64(file, static_cast<__int64>(offset), SEEK_SET) != 0)
        return false;

    if (length != 0 && std::fwrite(source, 1, length, file) != length)
        return false;

    return std::fflush(file) == 0;
}

// ---------------------------------------------------------------------------
// Rc4 - the game's RC4 variant. Key setup is standard RC4; `discard` bytes of
// key stream are thrown away before the first real byte, matching the call
// sub_7FF7FC3CAF80(..., seed + 256) in the game.
// ---------------------------------------------------------------------------
class Rc4
{
public:
    void Init(const std::uint8_t* key, std::size_t keyLength, std::uint32_t discard)
    {
        for (std::size_t i = 0; i < 256; ++i)
            m_state[i] = static_cast<std::uint8_t>(i);

        std::uint8_t j = 0;
        for (std::size_t i = 0; i < 256; ++i)
        {
            j = static_cast<std::uint8_t>(j + m_state[i] + key[i % keyLength]);
            std::swap(m_state[i], m_state[j]);
        }

        m_i = 0;
        m_j = 0;

        for (std::uint32_t i = 0; i < discard; ++i)
            Next();
    }

    void Crypt(std::uint8_t* data, std::size_t length)
    {
        for (std::size_t i = 0; i < length; ++i)
            data[i] ^= Next();
    }

private:
    std::uint8_t Next()
    {
        m_i = static_cast<std::uint8_t>(m_i + 1);
        m_j = static_cast<std::uint8_t>(m_j + m_state[m_i]);
        std::swap(m_state[m_i], m_state[m_j]);
        return m_state[static_cast<std::uint8_t>(m_state[m_i] + m_state[m_j])];
    }

    std::uint8_t m_state[256] = {};
    std::uint8_t m_i = 0;
    std::uint8_t m_j = 0;
};

// The trailer stores the key/GUID XORed with a six-byte mask derived from the
// payload size and checksum. The key starts at mask offset 32 (LOCK) or 20
// (LCK3); the GUID always starts at offset 0.
void BuildMask(std::uint32_t payloadSize, std::uint32_t sizeKey,
               std::uint16_t checksum, std::uint16_t checksumKey,
               std::uint8_t mask[6])
{
    const std::uint32_t a = payloadSize ^ sizeKey;
    const std::uint16_t b = static_cast<std::uint16_t>(checksum ^ checksumKey);
    std::memcpy(mask, &a, 4);
    std::memcpy(mask + 4, &b, 2);
}

void XorWithMask(std::uint8_t* destination, const std::uint8_t* source,
                 std::size_t length, const std::uint8_t mask[6],
                 std::size_t maskOffset)
{
    for (std::size_t i = 0; i < length; ++i)
        destination[i] = source[i] ^ mask[(maskOffset + i) % 6];
}

bool FindEocd(const std::uint8_t* data, std::size_t size, std::size_t& position)
{
    if (size < 22)
        return false;

    const std::size_t lowest =
        size > 22 + 0xFFFF ? size - 22 - 0xFFFF : 0;

    for (std::size_t i = size - 22;; --i)
    {
        if (ReadU32(data + i) == kEocdSignature)
        {
            const std::uint16_t commentLength = ReadU16(data + i + 20);
            if (i + 22 + commentLength <= size)
            {
                position = i;
                return true;
            }
        }

        if (i == lowest)
            break;
    }

    return false;
}

bool ParseCentralDirectory(const std::uint8_t* data, std::size_t size,
                           std::uint16_t totalEntries,
                           std::vector<Entry>& entries, std::string& error)
{
    entries.clear();
    entries.reserve(totalEntries);

    std::size_t position = 0;

    for (std::uint16_t index = 0; index < totalEntries; ++index)
    {
        if (position + 46 > size)
        {
            error = "central directory is truncated";
            return false;
        }

        if (ReadU32(data + position) != kCentralSignature)
        {
            error = "bad central directory signature";
            return false;
        }

        Entry entry;
        entry.flags = ReadU16(data + position + 8);
        entry.method = ReadU16(data + position + 10);
        entry.crc = ReadU32(data + position + 16);
        entry.compressedSize = ReadU32(data + position + 20);
        entry.uncompressedSize = ReadU32(data + position + 24);

        const std::uint16_t nameLength = ReadU16(data + position + 28);
        const std::uint16_t extraLength = ReadU16(data + position + 30);
        const std::uint16_t commentLength = ReadU16(data + position + 32);
        entry.localHeaderOffset = ReadU32(data + position + 42);

        if (entry.compressedSize == 0xFFFFFFFFu ||
            entry.uncompressedSize == 0xFFFFFFFFu ||
            entry.localHeaderOffset == 0xFFFFFFFFu)
        {
            error = "ZIP64 archives are not supported";
            return false;
        }

        if (position + 46 + nameLength + extraLength + commentLength > size)
        {
            error = "central directory entry is truncated";
            return false;
        }

        entry.name.assign(reinterpret_cast<const char*>(data + position + 46),
                          nameLength);
        entries.push_back(std::move(entry));

        position += 46 + nameLength + extraLength + commentLength;
    }

    return true;
}

bool LoadLocked(FILE* file, std::uint64_t fileSize,
                const std::uint8_t* trailer, std::size_t trailerSize,
                Format format, Archive& archive, std::string& error)
{
    archive.format = format;
    archive.fileSize = fileSize;
    archive.trailerOffset = fileSize - trailerSize;

    const std::uint8_t* keyCipher = nullptr;
    const std::uint8_t* guidCipher = nullptr;
    std::uint32_t sizeKey = 0;
    std::uint16_t checksumKey = 0;
    std::size_t keyMaskOffset = 0;

    if (format == Format::Locked62)
    {
        archive.seed = ReadU32(trailer + 4);
        keyCipher = trailer + 8;
        guidCipher = trailer + 24;
        archive.payloadSize = ReadU32(trailer + 56);
        sizeKey = kLockSizeKey;
        checksumKey = kLockChecksumKey;
        keyMaskOffset = 32;
    }
    else
    {
        const std::uint16_t version = ReadU16(trailer + 4);
        if (version != 0x0300)
        {
            error = "unsupported LCK3 trailer version";
            return false;
        }

        archive.seed = ReadU32(trailer + 10);
        keyCipher = trailer + 14;
        guidCipher = trailer + 30;
        archive.payloadSize = ReadU32(trailer + 50);
        sizeKey = kLck3SizeKey;
        checksumKey = kLck3ChecksumKey;
        keyMaskOffset = 20;
    }

    const std::uint16_t checksum = ReadU16(trailer + trailerSize - 2);

    std::uint8_t mask[6] = {};
    BuildMask(archive.payloadSize, sizeKey, checksum, checksumKey, mask);
    XorWithMask(archive.key, keyCipher, 16, mask, keyMaskOffset);
    XorWithMask(archive.guid, guidCipher, 16, mask, 0);

    if (archive.payloadSize == 0 || archive.payloadSize > archive.trailerOffset)
    {
        error = "invalid encrypted payload size";
        return false;
    }

    archive.payloadOffset = archive.trailerOffset - archive.payloadSize;

    std::vector<std::uint8_t> payload(archive.payloadSize);
    if (!ReadAt(file, archive.payloadOffset, payload.data(), payload.size()))
    {
        error = "could not read the encrypted central directory";
        return false;
    }

    Rc4 rc4;
    rc4.Init(archive.key, sizeof(archive.key), archive.seed + 256);
    rc4.Crypt(payload.data(), payload.size());

    std::uint16_t sum = 0;
    for (const std::uint8_t byte : payload)
        sum = static_cast<std::uint16_t>(sum + byte);

    if (sum != checksum)
    {
        error = "payload checksum mismatch (wrong key or damaged archive)";
        return false;
    }

    std::size_t eocdPosition = 0;
    if (!FindEocd(payload.data(), payload.size(), eocdPosition))
    {
        error = "ZIP end-of-central-directory record not found";
        return false;
    }

    const std::uint16_t totalEntries = ReadU16(payload.data() + eocdPosition + 10);
    const std::uint32_t centralSize = ReadU32(payload.data() + eocdPosition + 12);

    if (centralSize > eocdPosition)
    {
        error = "invalid central directory size";
        return false;
    }

    // The game's writer places the central directory at payload offset 0.
    // Deriving it from the EOCD also accepts layouts with padding.
    const std::size_t centralStart = eocdPosition - centralSize;

    if (!ParseCentralDirectory(payload.data() + centralStart,
                               eocdPosition - centralStart,
                               totalEntries, archive.entries, error))
    {
        return false;
    }

    return true;
}

bool LoadPlain(FILE* file, std::uint64_t fileSize, Archive& archive,
               std::string& error)
{
    archive.format = Format::PlainZip;
    archive.fileSize = fileSize;

    const std::uint64_t windowSize =
        std::min<std::uint64_t>(fileSize, 22 + 0xFFFF);
    std::vector<std::uint8_t> tail(static_cast<std::size_t>(windowSize));

    if (!ReadAt(file, fileSize - windowSize, tail.data(), tail.size()))
    {
        error = "could not read the end of the archive";
        return false;
    }

    std::size_t eocdInTail = 0;
    if (!FindEocd(tail.data(), tail.size(), eocdInTail))
    {
        error = "not a ZIP/pkz archive (no end-of-central-directory record)";
        return false;
    }

    const std::uint8_t* eocd = tail.data() + eocdInTail;
    const std::uint16_t totalEntries = ReadU16(eocd + 10);
    const std::uint32_t centralSize = ReadU32(eocd + 12);
    const std::uint32_t centralOffset = ReadU32(eocd + 16);

    if (static_cast<std::uint64_t>(centralOffset) + centralSize > fileSize)
    {
        error = "invalid central directory offset";
        return false;
    }

    std::vector<std::uint8_t> central(centralSize);
    if (!ReadAt(file, centralOffset, central.data(), central.size()))
    {
        error = "could not read the central directory";
        return false;
    }

    return ParseCentralDirectory(central.data(), central.size(), totalEntries,
                                 archive.entries, error);
}

bool NormalizeEntryName(const std::string& name, std::string& normalized)
{
    normalized.clear();

    std::string path = name;
    std::replace(path.begin(), path.end(), '\\', '/');

    if (path.empty() || path[0] == '/')
        return false;

    // Reject drive letters and embedded NULs.
    if ((path.size() >= 2 && path[1] == ':') ||
        path.find('\0') != std::string::npos)
    {
        return false;
    }

    std::size_t start = 0;
    while (start <= path.size())
    {
        const std::size_t slash = path.find('/', start);
        const std::string part =
            path.substr(start, slash == std::string::npos ? std::string::npos
                                                          : slash - start);

        if (part == "." || part == "..")
            return false;

        if (slash == std::string::npos)
            break;
        start = slash + 1;
    }

    normalized = std::move(path);
    return true;
}

std::uint32_t Crc32Update(std::uint32_t crc, const std::uint8_t* data,
                          std::size_t length)
{
    static std::uint32_t table[256] = {};
    static bool tableReady = false;

    if (!tableReady)
    {
        for (std::uint32_t i = 0; i < 256; ++i)
        {
            std::uint32_t value = i;
            for (int bit = 0; bit < 8; ++bit)
                value = (value & 1) ? (0xEDB88320u ^ (value >> 1)) : (value >> 1);
            table[i] = value;
        }
        tableReady = true;
    }

    for (std::size_t i = 0; i < length; ++i)
        crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);

    return crc;
}

std::uint32_t Crc32(const std::uint8_t* data, std::size_t length)
{
    return Crc32Update(0xFFFFFFFFu, data, length) ^ 0xFFFFFFFFu;
}

bool EntryDataOffset(FILE* file, const Archive& archive, const Entry& entry,
                     std::uint64_t& dataOffset, std::string& error)
{
    std::uint8_t header[30] = {};
    if (!ReadAt(file, entry.localHeaderOffset, header, sizeof(header)))
    {
        error = "could not read the local file header";
        return false;
    }

    if (archive.format != Format::PlainZip)
    {
        Rc4 rc4;
        rc4.Init(archive.key, sizeof(archive.key), archive.seed + 256);
        rc4.Crypt(header, sizeof(header));
    }

    if (ReadU32(header) != kLocalSignature)
    {
        error = "bad local file header signature";
        return false;
    }

    const std::uint16_t nameLength = ReadU16(header + 26);
    const std::uint16_t extraLength = ReadU16(header + 28);

    dataOffset = static_cast<std::uint64_t>(entry.localHeaderOffset) + 30 +
                 nameLength + extraLength;
    return true;
}

} // namespace

bool IsGuidLocked(const Archive& archive)
{
    for (const std::uint8_t byte : archive.guid)
    {
        if (byte != 0)
            return true;
    }
    return false;
}

std::string GuidString(const Archive& archive)
{
    char buffer[64] = {};
    std::snprintf(buffer, sizeof(buffer),
                  "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-"
                  "%02X%02X%02X%02X%02X%02X",
                  archive.guid[0], archive.guid[1], archive.guid[2],
                  archive.guid[3], archive.guid[4], archive.guid[5],
                  archive.guid[6], archive.guid[7], archive.guid[8],
                  archive.guid[9], archive.guid[10], archive.guid[11],
                  archive.guid[12], archive.guid[13], archive.guid[14],
                  archive.guid[15]);
    return buffer;
}

const char* FormatName(Format format)
{
    switch (format)
    {
    case Format::Locked62:
        return "LOCK (62-byte trailer)";
    case Format::Locked56:
        return "LCK3 (56-byte trailer)";
    default:
        return "plain ZIP";
    }
}

bool Open(const std::filesystem::path& path, Archive& archive,
          std::string& error)
{
    archive = Archive{};
    error.clear();

    FILE* file = _wfopen(path.c_str(), L"rb");
    if (!file)
    {
        error = "could not open the file";
        return false;
    }

    std::uint64_t fileSize = 0;
    if (!GetFileSize(file, fileSize))
    {
        error = "could not determine the file size";
        std::fclose(file);
        return false;
    }

    bool ok = false;

    if (fileSize >= 62)
    {
        std::uint8_t trailer[62] = {};
        if (ReadAt(file, fileSize - sizeof(trailer), trailer, sizeof(trailer)) &&
            ReadU32(trailer) == kLockMagic)
        {
            ok = LoadLocked(file, fileSize, trailer, sizeof(trailer),
                            Format::Locked62, archive, error);
            std::fclose(file);
            return ok;
        }
    }

    if (fileSize >= 56)
    {
        std::uint8_t trailer[56] = {};
        if (ReadAt(file, fileSize - sizeof(trailer), trailer, sizeof(trailer)) &&
            ReadU32(trailer) == kLck3Magic)
        {
            ok = LoadLocked(file, fileSize, trailer, sizeof(trailer),
                            Format::Locked56, archive, error);
            std::fclose(file);
            return ok;
        }
    }

    ok = LoadPlain(file, fileSize, archive, error);
    std::fclose(file);
    return ok;
}

bool RemoveGuidLock(const std::filesystem::path& path, bool& removed,
                    std::string& error)
{
    removed = false;
    error.clear();

    FILE* file = _wfopen(path.c_str(), L"r+b");
    if (!file)
    {
        error = "could not open the archive for writing";
        return false;
    }

    std::uint64_t fileSize = 0;
    if (!GetFileSize(file, fileSize))
    {
        error = "could not determine the archive size";
        std::fclose(file);
        return false;
    }

    std::uint8_t trailer[62] = {};
    std::size_t trailerSize = 0;
    std::size_t guidOffset = 0;
    std::uint32_t payloadSize = 0;
    std::uint16_t checksum = 0;
    std::uint32_t sizeKey = 0;
    std::uint16_t checksumKey = 0;

    if (fileSize >= 62)
    {
        std::uint8_t candidate[62] = {};
        if (!ReadAt(file, fileSize - 62, candidate, sizeof(candidate)))
        {
            error = "could not read the archive trailer";
            std::fclose(file);
            return false;
        }

        if (ReadU32(candidate) == kLockMagic)
        {
            std::memcpy(trailer, candidate, sizeof(candidate));
            trailerSize = 62;
            guidOffset = 24;
            payloadSize = ReadU32(trailer + 56);
            checksum = ReadU16(trailer + 60);
            sizeKey = kLockSizeKey;
            checksumKey = kLockChecksumKey;
        }
    }

    if (trailerSize == 0 && fileSize >= 56)
    {
        std::uint8_t candidate[56] = {};
        if (!ReadAt(file, fileSize - 56, candidate, sizeof(candidate)))
        {
            error = "could not read the archive trailer";
            std::fclose(file);
            return false;
        }

        if (ReadU32(candidate) == kLck3Magic)
        {
            if (ReadU16(candidate + 4) != 0x0300)
            {
                error = "unsupported LCK3 trailer version";
                std::fclose(file);
                return false;
            }

            std::memcpy(trailer, candidate, sizeof(candidate));
            trailerSize = 56;
            guidOffset = 30;
            payloadSize = ReadU32(trailer + 50);
            checksum = ReadU16(trailer + 54);
            sizeKey = kLck3SizeKey;
            checksumKey = kLck3ChecksumKey;
        }
    }

    if (trailerSize == 0)
    {
        error = "not a GUID-locked .pkz archive";
        std::fclose(file);
        return false;
    }

    std::uint8_t mask[6] = {};
    BuildMask(payloadSize, sizeKey, checksum, checksumKey, mask);

    bool locked = false;
    for (std::size_t i = 0; i < 16; ++i)
    {
        if ((trailer[guidOffset + i] ^ mask[i % 6]) != 0)
        {
            locked = true;
            break;
        }
    }

    if (!locked)
    {
        std::fclose(file);
        return true;
    }

    // Re-encoding an all-zero GUID gives the raw six-byte mask.
    std::uint8_t cleared[16] = {};
    for (std::size_t i = 0; i < sizeof(cleared); ++i)
        cleared[i] = mask[i % 6];

    const std::uint64_t guidFileOffset =
        fileSize - trailerSize + guidOffset;

    if (!WriteAt(file, guidFileOffset, cleared, sizeof(cleared)))
    {
        error = "could not write the archive trailer";
        std::fclose(file);
        return false;
    }

    std::uint8_t check[16] = {};
    if (!ReadAt(file, guidFileOffset, check, sizeof(check)) ||
        std::memcmp(check, cleared, sizeof(check)) != 0)
    {
        error = "GUID removal could not be verified";
        std::fclose(file);
        return false;
    }

    std::fclose(file);
    removed = true;
    return true;
}

bool Extract(const std::filesystem::path& path, const Archive& archive,
             const std::filesystem::path& outputDirectory,
             const ExtractOptions& options, ExtractStats& stats,
             std::string& error)
{
    stats = ExtractStats{};
    error.clear();

    FILE* file = _wfopen(path.c_str(), L"rb");
    if (!file)
    {
        error = "could not open the file";
        return false;
    }

    std::uint64_t fileSize = 0;
    if (!GetFileSize(file, fileSize))
    {
        error = "could not determine the file size";
        std::fclose(file);
        return false;
    }

    std::error_code ec;
    std::filesystem::create_directories(outputDirectory, ec);

    bool success = true;

    for (const Entry& entry : archive.entries)
    {
        std::string normalized;
        if (!NormalizeEntryName(entry.name, normalized))
        {
            std::fprintf(stderr, "  error: unsafe entry name: %s\n",
                         entry.name.c_str());
            ++stats.failed;
            success = false;
            continue;
        }

        const bool isDirectory =
            !normalized.empty() && normalized.back() == '/';

        std::filesystem::path destination;
        try
        {
            destination = outputDirectory / std::filesystem::u8path(normalized);
        }
        catch (const std::exception&)
        {
            std::fprintf(stderr, "  error: invalid entry path: %s\n",
                         entry.name.c_str());
            ++stats.failed;
            success = false;
            continue;
        }

        if (isDirectory)
        {
            std::filesystem::create_directories(destination, ec);
            ++stats.directories;
            continue;
        }

        std::filesystem::create_directories(destination.parent_path(), ec);

        if (!options.overwrite && std::filesystem::exists(destination, ec))
        {
            ++stats.skipped;
            continue;
        }

        if (entry.flags & 1)
        {
            std::fprintf(stderr,
                         "  error: %s uses unsupported ZipCrypto encryption\n",
                         entry.name.c_str());
            ++stats.failed;
            success = false;
            continue;
        }

        std::uint64_t dataOffset = 0;
        if (!EntryDataOffset(file, archive, entry, dataOffset, error))
        {
            std::fprintf(stderr, "  error: %s: %s\n", entry.name.c_str(),
                         error.c_str());
            ++stats.failed;
            success = false;
            continue;
        }

        if (entry.method == 0 &&
            entry.uncompressedSize != entry.compressedSize)
        {
            std::fprintf(stderr,
                         "  error: %s: stored entry has mismatched sizes\n",
                         entry.name.c_str());
            ++stats.failed;
            success = false;
            continue;
        }

        const std::uint64_t dataEnd =
            dataOffset + entry.compressedSize;
        if (dataEnd > fileSize ||
            (archive.format != Format::PlainZip && dataEnd > archive.payloadOffset))
        {
            std::fprintf(stderr, "  error: %s: data is outside the archive\n",
                         entry.name.c_str());
            ++stats.failed;
            success = false;
            continue;
        }

        std::uint32_t actualCrc = 0;

        if (entry.method == 0)
        {
            std::vector<std::uint8_t> buffer(1 << 20);
            std::ofstream output(destination, std::ios::binary | std::ios::trunc);
            if (!output)
            {
                std::fprintf(stderr, "  error: %s: could not create output\n",
                             entry.name.c_str());
                ++stats.failed;
                success = false;
                continue;
            }

            if (_fseeki64(file, static_cast<__int64>(dataOffset), SEEK_SET) != 0)
            {
                std::fprintf(stderr, "  error: %s: seek failed\n",
                             entry.name.c_str());
                ++stats.failed;
                success = false;
                continue;
            }

            std::uint32_t crc = 0xFFFFFFFFu;
            std::uint32_t remaining = entry.compressedSize;
            bool readOk = true;

            while (remaining != 0)
            {
                const std::size_t chunk =
                    std::min<std::size_t>(remaining, buffer.size());
                if (std::fread(buffer.data(), 1, chunk, file) != chunk)
                {
                    readOk = false;
                    break;
                }

                crc = Crc32Update(crc, buffer.data(), chunk);
                output.write(reinterpret_cast<const char*>(buffer.data()),
                             static_cast<std::streamsize>(chunk));
                remaining -= static_cast<std::uint32_t>(chunk);
            }

            if (!readOk || !output)
            {
                output.close();
                std::filesystem::remove(destination, ec);
                std::fprintf(stderr, "  error: %s: read/write failed\n",
                             entry.name.c_str());
                ++stats.failed;
                success = false;
                continue;
            }

            actualCrc = crc ^ 0xFFFFFFFFu;
        }
        else if (entry.method == 8)
        {
            std::vector<std::uint8_t> compressed(entry.compressedSize);
            if (!ReadAt(file, dataOffset, compressed.data(), compressed.size()))
            {
                std::fprintf(stderr, "  error: %s: could not read data\n",
                             entry.name.c_str());
                ++stats.failed;
                success = false;
                continue;
            }

            std::vector<std::uint8_t> decompressed(
                entry.uncompressedSize ? entry.uncompressedSize : 1);

            unsigned long destLength =
                static_cast<unsigned long>(entry.uncompressedSize);
            unsigned long srcLength =
                static_cast<unsigned long>(compressed.size());

            const int result = puff(decompressed.data(), &destLength,
                                    compressed.data(), &srcLength);

            if (result != 0 || destLength != entry.uncompressedSize)
            {
                std::fprintf(stderr,
                             "  error: %s: inflate failed (code %d, %lu of "
                             "%lu bytes)\n",
                             entry.name.c_str(), result, destLength,
                             static_cast<unsigned long>(
                                 entry.uncompressedSize));
                ++stats.failed;
                success = false;
                continue;
            }

            std::ofstream output(destination, std::ios::binary | std::ios::trunc);
            if (!output)
            {
                std::fprintf(stderr, "  error: %s: could not create output\n",
                             entry.name.c_str());
                ++stats.failed;
                success = false;
                continue;
            }

            output.write(reinterpret_cast<const char*>(decompressed.data()),
                         static_cast<std::streamsize>(destLength));

            if (!output)
            {
                output.close();
                std::filesystem::remove(destination, ec);
                std::fprintf(stderr, "  error: %s: write failed\n",
                             entry.name.c_str());
                ++stats.failed;
                success = false;
                continue;
            }

            actualCrc = Crc32(decompressed.data(), destLength);
        }
        else
        {
            std::fprintf(stderr,
                         "  error: %s: unsupported compression method %u\n",
                         entry.name.c_str(), entry.method);
            ++stats.failed;
            success = false;
            continue;
        }

        if (actualCrc != entry.crc)
        {
            std::filesystem::remove(destination, ec);
            std::fprintf(stderr,
                         "  error: %s: CRC mismatch (expected %08X, got %08X)\n",
                         entry.name.c_str(), entry.crc, actualCrc);
            ++stats.failed;
            success = false;
            continue;
        }

        ++stats.files;
        stats.bytes += entry.uncompressedSize;

        if (options.verbose)
        {
            std::printf("  %s (%u bytes)\n", entry.name.c_str(),
                        entry.uncompressedSize);
        }
    }

    std::fclose(file);
    return success;
}

} // namespace pkz
