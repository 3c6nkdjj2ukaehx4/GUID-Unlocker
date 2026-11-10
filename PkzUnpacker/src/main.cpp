// ============================================================================
//  PkzUnpacker - decrypt and extract GUID-locked MX Bikes .pkz archives
//
//  Run without arguments for the menu, or use the command line below.
// ============================================================================

#include "common.h"
#include "interactive.h"
#include "pkz.h"

#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <vector>

namespace {

void PrintUsage()
{
    std::printf(
        "PkzUnpacker - decrypt and extract MX Bikes .pkz archives\n"
        "\n"
        "Usage:\n"
        "  PkzUnpacker                          interactive menu\n"
        "  PkzUnpacker <archive.pkz | folder> [options]\n"
        "\n"
        "Options:\n"
        "  -o, --out <dir>    write extracted files to <dir>\n"
        "  -l, --list         list archive contents without extracting\n"
        "  -f, --force        overwrite files that already exist\n"
        "  -v, --verbose      print every extracted file\n"
        "  -r, --recurse      scan subfolders when the input is a folder\n"
        "  -q, --quiet        only print errors\n"
        "  -i, --interactive  open the interactive menu\n"
        "  --remove-guid      clear the GUID lock in the source archive\n"
        "  -h, --help         show this help\n"
        "\n"
        "GUID-locked archives are decrypted regardless of which GUID they are\n"
        "locked to; the lock value is only reported.\n");
}

std::string MethodName(std::uint16_t method)
{
    switch (method)
    {
    case 0:
        return "stored";
    case 8:
        return "deflate";
    default:
        return "method " + std::to_string(method);
    }
}

void PrintArchiveInfo(const std::filesystem::path& path,
                      const pkz::Archive& archive)
{
    std::printf("%s: %s, %zu entries",
                common::Narrow(path.filename()).c_str(),
                pkz::FormatName(archive.format), archive.entries.size());

    if (archive.format != pkz::Format::PlainZip)
    {
        if (pkz::IsGuidLocked(archive))
            std::printf(", GUID lock %s", pkz::GuidString(archive).c_str());
        else
            std::printf(", no GUID lock");
    }

    std::printf("\n");
}

void PrintEntries(const pkz::Archive& archive)
{
    for (const pkz::Entry& entry : archive.entries)
    {
        std::printf("  %-12s %10u -> %10u  %s\n",
                    MethodName(entry.method).c_str(),
                    entry.compressedSize, entry.uncompressedSize,
                    entry.name.c_str());
    }
}

std::vector<std::filesystem::path> CollectArchives(
    const std::vector<std::filesystem::path>& inputs, bool recurse,
    bool& anyError)
{
    std::vector<std::filesystem::path> archives;

    for (const std::filesystem::path& input : inputs)
    {
        std::error_code ec;

        if (std::filesystem::is_regular_file(input, ec))
        {
            archives.push_back(input);
            continue;
        }

        if (!std::filesystem::is_directory(input, ec))
        {
            std::fprintf(stderr, "error: %s: no such file or folder\n",
                         common::Narrow(input).c_str());
            anyError = true;
            continue;
        }

        if (recurse)
        {
            for (std::filesystem::recursive_directory_iterator it(input, ec), end;
                 it != end; it.increment(ec))
            {
                if (ec)
                {
                    std::fprintf(stderr, "error: %s: %s\n",
                                 common::Narrow(input).c_str(),
                                 ec.message().c_str());
                    anyError = true;
                    ec.clear();
                    break;
                }

                if (it->is_regular_file(ec) && common::IsPkzFile(it->path()))
                    archives.push_back(it->path());
            }
        }
        else
        {
            for (std::filesystem::directory_iterator it(input, ec), end;
                 it != end; it.increment(ec))
            {
                if (ec)
                {
                    std::fprintf(stderr, "error: %s: %s\n",
                                 common::Narrow(input).c_str(),
                                 ec.message().c_str());
                    anyError = true;
                    ec.clear();
                    break;
                }

                if (it->is_regular_file(ec) && common::IsPkzFile(it->path()))
                    archives.push_back(it->path());
            }
        }
    }

    std::sort(archives.begin(), archives.end(),
              [](const std::filesystem::path& a,
                 const std::filesystem::path& b)
              { return a.wstring() < b.wstring(); });

    return archives;
}

} // namespace

int wmain(int argc, wchar_t** argv)
{
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    if (argc <= 1)
        return pkzapp::RunInteractive();

    std::vector<std::filesystem::path> inputs;
    std::filesystem::path outputDirectory;
    bool listOnly = false;
    bool overwrite = false;
    bool verbose = false;
    bool recurse = false;
    bool quiet = false;
    bool removeGuid = false;

    for (int i = 1; i < argc; ++i)
    {
        const std::wstring argument = argv[i];

        if (argument == L"-h" || argument == L"--help")
        {
            PrintUsage();
            return 0;
        }
        if (argument == L"-i" || argument == L"--interactive")
            return pkzapp::RunInteractive();
        if (argument == L"-o" || argument == L"--out")
        {
            if (++i >= argc)
            {
                std::fprintf(stderr, "error: %s requires a directory\n",
                             common::Narrow(argument).c_str());
                return 1;
            }
            outputDirectory = argv[i];
            continue;
        }
        if (argument == L"-l" || argument == L"--list")
        {
            listOnly = true;
            continue;
        }
        if (argument == L"-f" || argument == L"--force")
        {
            overwrite = true;
            continue;
        }
        if (argument == L"-v" || argument == L"--verbose")
        {
            verbose = true;
            continue;
        }
        if (argument == L"-r" || argument == L"--recurse")
        {
            recurse = true;
            continue;
        }
        if (argument == L"-q" || argument == L"--quiet")
        {
            quiet = true;
            continue;
        }
        if (argument == L"--remove-guid")
        {
            removeGuid = true;
            continue;
        }
        if (!argument.empty() && argument[0] == L'-')
        {
            std::fprintf(stderr, "error: unknown option %s\n",
                         common::Narrow(argument).c_str());
            PrintUsage();
            return 1;
        }

        inputs.emplace_back(argument);
    }

    if (inputs.empty())
    {
        PrintUsage();
        return 1;
    }

    bool inputError = false;
    const std::vector<std::filesystem::path> archives =
        CollectArchives(inputs, recurse, inputError);

    if (archives.empty())
    {
        if (!inputError)
            std::fprintf(stderr, "error: no .pkz archives found\n");
        return 1;
    }

    std::error_code singleInputError;
    const bool singleFileInput =
        inputs.size() == 1 &&
        std::filesystem::is_regular_file(inputs[0], singleInputError);

    pkz::ExtractStats totals;
    bool failed = inputError;
    std::size_t archiveCount = 0;

    for (const std::filesystem::path& path : archives)
    {
        pkz::Archive archive;
        std::string error;

        if (!pkz::Open(path, archive, error))
        {
            std::fprintf(stderr, "error: %s: %s\n",
                         common::Narrow(path).c_str(), error.c_str());
            failed = true;
            continue;
        }

        ++archiveCount;

        if (!quiet)
            PrintArchiveInfo(path, archive);

        if (listOnly)
        {
            PrintEntries(archive);
            continue;
        }

        std::filesystem::path destination;
        if (!outputDirectory.empty())
            destination = singleFileInput ? outputDirectory
                                          : outputDirectory / path.stem();
        else
            destination = path.parent_path() / path.stem();

        pkz::ExtractOptions options;
        options.overwrite = overwrite;
        options.verbose = verbose && !quiet;

        pkz::ExtractStats stats;
        std::string extractError;

        const bool ok = pkz::Extract(path, archive, destination, options, stats,
                                     extractError);

        if (!extractError.empty())
        {
            std::fprintf(stderr, "error: %s: %s\n",
                         common::Narrow(path).c_str(),
                         extractError.c_str());
            failed = true;
            continue;
        }

        if (!ok)
            failed = true;

        bool guidRemoved = false;
        if (ok && removeGuid && archive.format != pkz::Format::PlainZip &&
            pkz::IsGuidLocked(archive))
        {
            bool removed = false;
            std::string guidError;
            if (!pkz::RemoveGuidLock(path, removed, guidError))
            {
                std::fprintf(stderr, "error: %s: %s\n",
                             common::Narrow(path).c_str(),
                             guidError.c_str());
                failed = true;
            }
            else
            {
                guidRemoved = removed;
            }
        }

        totals.files += stats.files;
        totals.directories += stats.directories;
        totals.skipped += stats.skipped;
        totals.failed += stats.failed;
        totals.bytes += stats.bytes;

        if (!quiet)
        {
            std::printf("  extracted %zu files (%s)", stats.files,
                        common::HumanBytes(stats.bytes).c_str());

            if (stats.skipped != 0)
                std::printf(", %zu skipped", stats.skipped);
            if (stats.failed != 0)
                std::printf(", %zu failed", stats.failed);
            if (guidRemoved)
                std::printf(", GUID removed");

            std::printf(" -> %s\n",
                        common::Narrow(destination).c_str());
        }
    }

    if (!quiet && archiveCount > 1)
    {
        std::printf("\n%zu archives: %zu files (%s)", archiveCount,
                    totals.files, common::HumanBytes(totals.bytes).c_str());

        if (totals.skipped != 0)
            std::printf(", %zu skipped", totals.skipped);
        if (totals.failed != 0)
            std::printf(", %zu failed", totals.failed);

        std::printf("\n");
    }

    return failed ? 1 : 0;
}
