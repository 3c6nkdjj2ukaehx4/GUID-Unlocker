// ============================================================================
//  PkzUnpacker - decrypt and extract MX Bikes .pkz archives
//
//  Handles the GUID-locked .pkz format written by MX Bikes mod tools:
//
//      [ local headers + file data ][ encrypted central directory ][ trailer ]
//
//  The trailer carries the 16-byte GUID, an RC4 key and a payload checksum.
//  The central directory and every local header/file name are RC4-encrypted
//  (the file data itself is stored as a normal ZIP: stored or raw deflate).
//
//  Two trailer layouts exist:
//
//      62-byte "LOCK" trailer  (current)
//      56-byte "LCK3" trailer  (legacy)
//
//  Plain, unencrypted ZIPs (the stock game .pkz files) are also supported.
// ============================================================================

#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace pkz {

enum class Format
{
    PlainZip,
    Locked62,
    Locked56,
};

struct Entry
{
    std::string name;
    std::uint16_t flags = 0;
    std::uint16_t method = 0;
    std::uint32_t crc = 0;
    std::uint32_t compressedSize = 0;
    std::uint32_t uncompressedSize = 0;
    std::uint32_t localHeaderOffset = 0;
};

struct Archive
{
    Format format = Format::PlainZip;
    std::uint8_t guid[16] = {};
    std::uint8_t key[16] = {};
    std::uint32_t seed = 0;
    std::uint64_t fileSize = 0;
    std::uint64_t trailerOffset = 0;
    std::uint64_t payloadOffset = 0;
    std::uint32_t payloadSize = 0;
    std::vector<Entry> entries;
};

struct ExtractOptions
{
    bool overwrite = false;
    bool verbose = false;
};

struct ExtractStats
{
    std::size_t files = 0;
    std::size_t directories = 0;
    std::size_t skipped = 0;
    std::size_t failed = 0;
    std::uint64_t bytes = 0;
};

// Opens an archive and reads/decrypts its central directory. The GUID lock is
// reported, never enforced.
bool Open(const std::filesystem::path& path, Archive& archive, std::string& error);

// Extracts every entry into outputDirectory. Individual entry failures are
// counted in stats and printed; the return value is false if any entry failed.
bool Extract(const std::filesystem::path& path, const Archive& archive,
             const std::filesystem::path& outputDirectory,
             const ExtractOptions& options, ExtractStats& stats, std::string& error);

// Clears the 16-byte GUID lock stored in the archive trailer. Only the trailer
// GUID field is rewritten; the encrypted contents and key are untouched.
// `removed` is false when the archive was already unlocked.
bool RemoveGuidLock(const std::filesystem::path& path, bool& removed,
                    std::string& error);

bool IsGuidLocked(const Archive& archive);
std::string GuidString(const Archive& archive);
const char* FormatName(Format format);

} // namespace pkz
