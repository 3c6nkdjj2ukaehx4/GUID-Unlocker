#include "interactive.h"

#include "common.h"
#include "pkz.h"

#include <windows.h>
#include <shlobj.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <filesystem>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace pkzapp {
namespace {

namespace fs = std::filesystem;

struct ScannedArchive
{
    fs::path path;
    fs::path root;
    fs::path relative;
    std::string category;
    std::string commonTopLevel;
    std::uint64_t fileSize = 0;
    pkz::Format format = pkz::Format::PlainZip;
    std::size_t entries = 0;
    bool openOk = false;
    bool encrypted = false;
    bool guidLocked = false;
    std::string guid = "-";
    std::string error;
};

std::string ReadLine(const char* prompt)
{
    std::printf("%s", prompt);
    std::fflush(stdout);

    std::string line;
    if (!std::getline(std::cin, line))
        return {};

    return common::Trim(line);
}

void Pause()
{
    ReadLine("\nPress Enter to continue...");
}

void ClearScreen()
{
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO info;
    if (output == INVALID_HANDLE_VALUE ||
        !GetConsoleScreenBufferInfo(output, &info))
    {
        return;
    }

    const DWORD cells = static_cast<DWORD>(info.dwSize.X) *
                        static_cast<DWORD>(info.dwSize.Y);
    const COORD home = { 0, 0 };
    DWORD written = 0;
    FillConsoleOutputCharacterW(output, L' ', cells, home, &written);
    FillConsoleOutputAttribute(output, info.wAttributes, cells, home,
                               &written);
    SetConsoleCursorPosition(output, home);
}

bool IsYes(const std::string& answer)
{
    const std::string lower = common::Lower(common::Trim(answer));
    return lower == "y" || lower == "yes";
}

int ParseNumber(const std::string& text, int maximum)
{
    if (text.empty())
        return -1;

    char* end = nullptr;
    const long value = std::strtol(text.c_str(), &end, 10);
    if (end == text.c_str() || *end != '\0' || value < 0 || value > maximum)
        return -1;

    return static_cast<int>(value);
}

fs::path ExecutableDirectory()
{
    std::vector<wchar_t> buffer(32768);
    const DWORD length = GetModuleFileNameW(nullptr, buffer.data(),
                                            static_cast<DWORD>(buffer.size()));
    if (length == 0)
        return fs::current_path();

    return fs::path(std::wstring(buffer.data(), length)).parent_path();
}

void AddSteamRoot(std::vector<fs::path>& candidates, HKEY hive,
                  const wchar_t* subkey, const wchar_t* valueName,
                  REGSAM extraAccess)
{
    HKEY key = nullptr;
    if (RegOpenKeyExW(hive, subkey, 0, KEY_READ | extraAccess, &key) !=
        ERROR_SUCCESS)
    {
        return;
    }

    wchar_t steamPath[32768] = {};
    DWORD size = sizeof(steamPath);
    DWORD type = 0;
    const LSTATUS status =
        RegQueryValueExW(key, valueName, nullptr, &type,
                         reinterpret_cast<LPBYTE>(steamPath), &size);
    RegCloseKey(key);

    if (status != ERROR_SUCCESS || type != REG_SZ || size < sizeof(wchar_t))
        return;

    steamPath[32767] = L'\0';
    candidates.push_back(fs::path(steamPath) / L"steamapps" / L"common" /
                         L"MX Bikes" / L"mods");
}

std::vector<fs::path> FindModsRoots()
{
    // An explicit override is handy for custom installs and for testing.
    wchar_t overridePath[32768] = {};
    const DWORD overrideLength =
        GetEnvironmentVariableW(L"MXBIKES_MODS", overridePath,
                                static_cast<DWORD>(std::size(overridePath)));
    if (overrideLength > 0 && overrideLength < std::size(overridePath))
    {
        std::error_code ec;
        const fs::path root(overridePath);
        if (fs::is_directory(root, ec))
            return { root };
    }

    std::vector<fs::path> candidates;

    PWSTR documents = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Documents, KF_FLAG_DEFAULT,
                                       nullptr, &documents)))
    {
        candidates.push_back(fs::path(documents) / L"PiBoSo" / L"MX Bikes" /
                             L"mods");
        CoTaskMemFree(documents);
    }

    const auto addEnvironmentRoot =
        [&candidates](const wchar_t* variable, const wchar_t* suffix)
    {
        wchar_t value[32768] = {};
        const DWORD length =
            GetEnvironmentVariableW(variable, value,
                                    static_cast<DWORD>(std::size(value)));
        if (length > 0 && length < std::size(value))
            candidates.push_back(fs::path(value) / suffix);
    };

    addEnvironmentRoot(L"USERPROFILE", L"Documents\\PiBoSo\\MX Bikes\\mods");
    addEnvironmentRoot(L"OneDrive", L"Documents\\PiBoSo\\MX Bikes\\mods");
    addEnvironmentRoot(L"OneDriveConsumer", L"Documents\\PiBoSo\\MX Bikes\\mods");
    addEnvironmentRoot(L"OneDriveCommercial", L"Documents\\PiBoSo\\MX Bikes\\mods");

    AddSteamRoot(candidates, HKEY_CURRENT_USER, L"Software\\Valve\\Steam",
                 L"SteamPath", 0);
    AddSteamRoot(candidates, HKEY_LOCAL_MACHINE,
                 L"SOFTWARE\\WOW6432Node\\Valve\\Steam", L"InstallPath",
                 KEY_WOW64_32KEY);
    candidates.emplace_back(
        L"C:\\Program Files (x86)\\Steam\\steamapps\\common\\MX Bikes\\mods");

    std::vector<fs::path> roots;
    std::set<std::wstring> seen;

    for (const fs::path& candidate : candidates)
    {
        std::error_code ec;
        if (!fs::is_directory(candidate, ec))
            continue;

        fs::path canonical = fs::weakly_canonical(candidate, ec);
        if (ec)
            canonical = candidate;

        if (seen.insert(common::Lower(canonical.wstring())).second)
            roots.push_back(canonical);
    }

    return roots;
}

std::string CommonTopLevel(const pkz::Archive& archive)
{
    std::string topLevel;

    for (const pkz::Entry& entry : archive.entries)
    {
        std::string name = entry.name;
        std::replace(name.begin(), name.end(), '\\', '/');

        const std::size_t slash = name.find('/');
        if (slash == std::string::npos || slash == 0)
            return {};

        const std::string first = name.substr(0, slash);
        if (first == "." || first == "..")
            return {};

        if (topLevel.empty())
            topLevel = first;
        else if (topLevel != first)
            return {};
    }

    return topLevel;
}

std::string CategoryOf(const fs::path& relative)
{
    auto it = relative.begin();
    if (it == relative.end())
        return "mods";

    auto next = it;
    ++next;
    if (next == relative.end())
        return "mods";

    return common::Narrow(it->wstring());
}

std::vector<ScannedArchive> ScanArchives(const std::vector<fs::path>& roots)
{
    std::vector<ScannedArchive> archives;

    for (const fs::path& root : roots)
    {
        std::error_code ec;
        for (fs::recursive_directory_iterator it(
                 root, fs::directory_options::skip_permission_denied, ec),
             end;
             it != end; it.increment(ec))
        {
            if (ec)
            {
                ec.clear();
                continue;
            }

            std::error_code entryError;
            if (!it->is_regular_file(entryError) ||
                !common::IsPkzFile(it->path()))
            {
                continue;
            }

            ScannedArchive item;
            item.path = it->path();
            item.root = root;
            item.relative = fs::relative(item.path, root, entryError);
            if (entryError)
                item.relative = item.path.filename();
            item.category = CategoryOf(item.relative);
            item.fileSize = fs::file_size(item.path, entryError);

            pkz::Archive archive;
            std::string error;
            item.openOk = pkz::Open(item.path, archive, error);
            if (item.openOk)
            {
                item.format = archive.format;
                item.encrypted = archive.format != pkz::Format::PlainZip;
                item.guidLocked = pkz::IsGuidLocked(archive);
                item.guid = item.guidLocked ? pkz::GuidString(archive) : "-";
                item.entries = archive.entries.size();
                item.commonTopLevel = CommonTopLevel(archive);
            }
            else
            {
                item.error = error;
            }

            if (item.openOk && item.guidLocked)
                archives.push_back(std::move(item));
        }
    }

    std::sort(archives.begin(), archives.end(),
              [](const ScannedArchive& a, const ScannedArchive& b)
              {
                  const std::string categoryA = common::Lower(a.category);
                  const std::string categoryB = common::Lower(b.category);
                  if (categoryA != categoryB)
                      return categoryA < categoryB;
                  return common::Lower(common::Narrow(a.relative)) <
                         common::Lower(common::Narrow(b.relative));
              });

    return archives;
}

void PrintSummary(const std::vector<fs::path>& roots,
                  const std::vector<ScannedArchive>& archives)
{
    std::printf("MX Bikes mods folders:\n");
    for (const fs::path& root : roots)
        std::printf("  %s\n", common::Narrow(root).c_str());

    std::size_t guidLocked = 0;
    std::map<std::string, std::size_t> categories;

    for (const ScannedArchive& archive : archives)
    {
        if (archive.guidLocked)
            ++guidLocked;
        ++categories[archive.category];
    }

    std::printf("\nFound %zu GUID-locked .pkz files\n", guidLocked);

    for (const auto& [category, count] : categories)
        std::printf("  %-12s %zu\n", category.c_str(), count);
}

void PrintScreen(const std::vector<fs::path>& roots,
                 const std::vector<ScannedArchive>& archives)
{
    ClearScreen();

    std::printf("============================================================\n");
    std::printf(" MX Bikes PKZ Unpacker\n");
    std::printf("============================================================\n\n");

    PrintSummary(roots, archives);

    std::printf(
        "\n  1) Decrypt ONE GUID-locked archive -> keep in game mods folder\n"
        "  2) Decrypt ONE GUID-locked archive -> output folder next to this app\n"
        "  3) Decrypt ALL GUID-locked archives -> keep in game mods folder\n"
        "  4) Decrypt ALL GUID-locked archives -> output folder next to this app\n"
        "  5) Show found archives\n"
        "  0) Exit\n"
        "\n  Successful decryptions also clear the GUID from the source .pkz.\n\n");
}

std::vector<std::size_t> AllIndices(const std::vector<ScannedArchive>& archives)
{
    std::vector<std::size_t> indices(archives.size());
    for (std::size_t i = 0; i < archives.size(); ++i)
        indices[i] = i;
    return indices;
}

std::vector<std::size_t> FilterArchives(
    const std::vector<ScannedArchive>& archives, const std::string& filter)
{
    const std::string needle = common::Lower(filter);
    std::vector<std::size_t> matches;

    for (std::size_t i = 0; i < archives.size(); ++i)
    {
        if (needle.empty() ||
            common::Lower(common::Narrow(archives[i].relative))
                    .find(needle) != std::string::npos)
        {
            matches.push_back(i);
        }
    }

    return matches;
}

std::string TypeName(const ScannedArchive& archive)
{
    if (!archive.openOk)
        return "ERR";

    switch (archive.format)
    {
    case pkz::Format::Locked62:
        return "LOCK";
    case pkz::Format::Locked56:
        return "LCK3";
    default:
        return "ZIP";
    }
}

void PrintTable(const std::vector<ScannedArchive>& archives,
                const std::vector<std::size_t>& indices)
{
    std::printf("\n%4s  %-5s %-10s %10s  %-36s  %s\n", "#", "Type",
                "Category", "Size", "GUID", "File");
    std::printf("%s\n", std::string(110, '-').c_str());

    for (std::size_t i = 0; i < indices.size(); ++i)
    {
        const ScannedArchive& archive = archives[indices[i]];
        std::printf("%4zu  %-5s %-10s %10s  %-36s  %s\n", i + 1,
                    TypeName(archive).c_str(), archive.category.c_str(),
                    common::HumanBytes(archive.fileSize).c_str(),
                    archive.guid.c_str(),
                    common::Narrow(archive.relative).c_str());
    }
}

int PickOne(const std::vector<ScannedArchive>& archives)
{
    const std::string filter =
        ReadLine("Filter by name/category (blank = show all): ");

    const std::vector<std::size_t> matches = FilterArchives(archives, filter);
    if (matches.empty())
    {
        std::printf("No archives match that filter.\n");
        return -1;
    }

    PrintTable(archives, matches);

    const std::string number =
        ReadLine("\nArchive number (0 = cancel): ");
    const int selected = ParseNumber(number, static_cast<int>(matches.size()));

    if (selected <= 0)
        return -1;

    return static_cast<int>(matches[selected - 1]);
}

bool ExtractSelected(std::vector<ScannedArchive>& archives,
                     const std::vector<std::size_t>& indices, bool keepInGame,
                     const fs::path& outputRoot, bool overwrite)
{
    pkz::ExtractStats total;
    std::size_t complete = 0;
    std::size_t failedArchives = 0;
    std::size_t guidsRemoved = 0;

    for (std::size_t i = 0; i < indices.size(); ++i)
    {
        ScannedArchive& item = archives[indices[i]];
        ++complete;

        if (!item.openOk)
        {
            std::fprintf(stderr, "  error: %s: %s\n",
                         common::Narrow(item.relative).c_str(),
                         item.error.c_str());
            ++failedArchives;
            continue;
        }

        pkz::Archive archive;
        std::string error;
        if (!pkz::Open(item.path, archive, error))
        {
            std::fprintf(stderr, "  error: %s: %s\n",
                         common::Narrow(item.relative).c_str(),
                         error.c_str());
            ++failedArchives;
            continue;
        }

        fs::path destination;
        if (keepInGame)
        {
            destination = item.path.parent_path();
            if (item.commonTopLevel.empty())
                destination /= item.path.stem();
        }
        else
        {
            destination = outputRoot / fs::u8path(item.category);
            if (item.commonTopLevel.empty())
                destination /= item.path.stem();
        }

        pkz::ExtractOptions options;
        options.overwrite = overwrite;
        options.verbose = false;

        pkz::ExtractStats stats;
        const bool ok = pkz::Extract(item.path, archive, destination, options,
                                     stats, error);

        bool guidRemovalAttempted = false;
        bool guidRemoved = false;
        std::string guidError;

        if (ok && error.empty() && item.guidLocked)
        {
            guidRemovalAttempted = true;
            bool removed = false;

            if (!pkz::RemoveGuidLock(item.path, removed, guidError))
            {
                std::fprintf(stderr, "  error: %s: %s\n",
                             common::Narrow(item.relative).c_str(),
                             guidError.c_str());
                ++failedArchives;
            }
            else
            {
                guidRemoved = removed;
                item.guidLocked = false;
                item.guid = "-";
                if (guidRemoved)
                    ++guidsRemoved;
            }
        }

        std::printf("[%zu/%zu] %s: %zu files", complete, indices.size(),
                    common::Narrow(item.relative).c_str(), stats.files);
        if (stats.skipped != 0)
            std::printf(", %zu skipped", stats.skipped);
        if (stats.failed != 0)
            std::printf(", %zu failed", stats.failed);
        if (guidRemoved)
            std::printf(", GUID removed");
        else if (guidRemovalAttempted && !guidError.empty())
            std::printf(", GUID removal FAILED");
        std::printf(" (%s)\n", common::HumanBytes(stats.bytes).c_str());

        if (!error.empty())
        {
            std::fprintf(stderr, "  error: %s: %s\n",
                         common::Narrow(item.relative).c_str(),
                         error.c_str());
            ++failedArchives;
        }
        else if (!ok)
        {
            ++failedArchives;
        }

        total.files += stats.files;
        total.directories += stats.directories;
        total.skipped += stats.skipped;
        total.failed += stats.failed;
        total.bytes += stats.bytes;
    }

    std::printf("\nDone: %zu archive(s), %zu files (%s)", complete,
                total.files, common::HumanBytes(total.bytes).c_str());
    if (total.skipped != 0)
        std::printf(", %zu skipped", total.skipped);
    if (total.failed != 0)
        std::printf(", %zu failed files", total.failed);
    if (guidsRemoved != 0)
        std::printf(", %zu GUID(s) removed", guidsRemoved);
    if (failedArchives != 0)
        std::printf(", %zu failed archive(s)", failedArchives);
    std::printf("\n");

    return failedArchives == 0 && total.failed == 0;
}

} // namespace

int RunInteractive()
{
    SetConsoleTitleW(L"MX Bikes PKZ Unpacker");

    std::vector<fs::path> roots = FindModsRoots();

    while (roots.empty())
    {
        std::printf("MX Bikes mods folder was not found automatically.\n");
        const std::string manual =
            ReadLine("Enter the mods folder path (blank to exit): ");
        if (manual.empty())
            return 1;

        std::error_code ec;
        const fs::path path = fs::u8path(manual);
        if (fs::is_directory(path, ec))
            roots.push_back(path);
        else
            std::printf("Not a folder: %s\n\n", manual.c_str());
    }

    std::printf("Scanning for .pkz files...\n");
    std::vector<ScannedArchive> archives = ScanArchives(roots);

    if (archives.empty())
    {
        std::printf("No GUID-locked .pkz files were found.\n");
        Pause();
        return 1;
    }

    const fs::path outputRoot = ExecutableDirectory() / L"output";

    PrintScreen(roots, archives);

    while (true)
    {
        const std::string choice = ReadLine("Select an option: ");

        if (choice == "0")
            break;

        if (choice == "5")
        {
            PrintTable(archives, AllIndices(archives));
            Pause();
            PrintScreen(roots, archives);
            continue;
        }

        if (choice != "1" && choice != "2" && choice != "3" &&
            choice != "4")
        {
            std::printf("Invalid option.\n");
            continue;
        }

        const bool keepInGame = (choice == "1" || choice == "3");
        const bool processAll = (choice == "3" || choice == "4");

        std::vector<std::size_t> indices;

        if (processAll)
        {
            for (std::size_t i = 0; i < archives.size(); ++i)
            {
                if (archives[i].openOk)
                    indices.push_back(i);
            }

            if (indices.empty())
            {
                std::printf("No GUID-locked archives were found.\n");
                Pause();
                PrintScreen(roots, archives);
                continue;
            }

            std::printf("\nThis will process %zu GUID-locked archive(s).\n",
                        indices.size());
        }
        else
        {
            const int selected = PickOne(archives);
            if (selected < 0)
                continue;
            indices.push_back(static_cast<std::size_t>(selected));
        }

        if (keepInGame)
        {
            std::printf("\nDestination: next to each .pkz inside the MX Bikes "
                        "mods folder.\n");
        }
        else
        {
            std::printf("\nDestination: %s\n"
                        "             (subfolders are created per category)\n",
                        common::Narrow(outputRoot).c_str());
        }

        const bool overwrite = IsYes(
            ReadLine("Overwrite files that already exist? [y/N]: "));

        if (processAll &&
            !IsYes(ReadLine("Continue? [y/N]: ")))
        {
            continue;
        }

        ExtractSelected(archives, indices, keepInGame, outputRoot,
                        overwrite);
        archives.erase(
            std::remove_if(archives.begin(), archives.end(),
                           [](const ScannedArchive& archive)
                           { return !archive.guidLocked; }),
            archives.end());
        Pause();
        PrintScreen(roots, archives);
    }

    std::printf("\nPress Enter to exit...");
    std::fflush(stdout);
    std::string ignored;
    std::getline(std::cin, ignored);
    return 0;
}

} // namespace pkzapp
