// ============================================================================
//  MxBikesGuidBypass
//
//  Rewrites the GUID comparisons inside:
//
//      sub_7FF7FC3C7920        RVA 0x157920
//
//  The function reads the 16-byte GUID structure:
//
//      qword_7FF7FC606770      RVA 0x396770   (0x01100001276121D4, no FF)
//      qword_7FF7FC606778      RVA 0x396778   (0xFF marker)
//
//  and contains two copies of the check (new and old .pkz header):
//
//      49 3B 96 70 67 39 00    cmp rdx, [r14+0x396770]
//      75 12                   jnz fail
//      48 8B 50 08             mov rdx, [rax+8]
//      49 3B 96 78 67 39 00    cmp rdx, [r14+0x396778]
//      75 05                   jnz fail
//
//  The rewrite is a direct in-place patch of those comparisons:
//
//      49 3B 96 70 67 39 00 -> 48 3B D2 90 90 90 90   (cmp rdx, rdx)
//      49 3B 96 78 67 39 00 -> 48 3B D2 90 90 90 90   (cmp rdx, rdx)
//      44 39 2D <disp32>    -> 45 3B ED 90 90 90 90   (cmp r13d, r13d)
//
//  There is no MinHook detour and no new sub function. The original
//  sub_7FF7FC3C7920 keeps executing; it just can no longer reject an archive
//  because of the GUID.
// ============================================================================

#include <windows.h>
#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <share.h>
#include <string>

namespace {

// Original IDA names. RVAs are relative to the main module base.
constexpr std::uintptr_t sub_7FF7FC3C7920 = 0x157920;
constexpr std::uintptr_t sub_7FF7FC3C9A40 = 0x159A40;
constexpr std::uintptr_t sub_7FF7FC3C9A40_size = 0x90F;
constexpr std::uintptr_t sub_7FF7FC3C9640 = 0x159640;
constexpr std::uintptr_t sub_7FF7FC3C9650 = 0x159650;
constexpr std::uintptr_t sub_7FF7FC3C9660 = 0x159660;
constexpr std::uintptr_t qword_7FF7FC606770 = 0x396770;
constexpr std::uintptr_t qword_7FF7FC606778 = 0x396778;
constexpr std::uintptr_t dword_7FF7FC60676C = 0x39676C;

// Track list rebuild (FrostMod's "tracks" reload row).
constexpr std::uintptr_t sub_7FF7FC272460 = 0x2460;      // track list loader
constexpr std::uintptr_t dword_7FF7FD1B3298 = 0xF43298;  // track count
constexpr std::uintptr_t qword_7FF7FD30DE98 = 0x109DE98; // track list pointer

HMODULE g_self = nullptr;
std::uintptr_t g_base = 0;
const std::uint8_t* g_textBegin = nullptr;
const std::uint8_t* g_textEnd = nullptr;

SRWLOCK g_logLock = SRWLOCK_INIT;
FILE* g_log = nullptr;
bool g_logEnabled = true;

HWND g_gameWindow = nullptr;
WNDPROC g_originalWndProc = nullptr;
UINT g_reloadMessage = 0;
std::atomic<bool> g_trackReloadDone{ false };

// ---------------------------------------------------------------------------
// logging
// ---------------------------------------------------------------------------
void Log(const char* fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    AcquireSRWLockExclusive(&g_logLock);
    if (g_logEnabled && g_log)
    {
        std::fprintf(g_log, "%s\n", buf);
        std::fflush(g_log);
    }
    ReleaseSRWLockExclusive(&g_logLock);

    OutputDebugStringA(buf);
    OutputDebugStringA("\n");
}

// ---------------------------------------------------------------------------
// compare helpers
// ---------------------------------------------------------------------------
std::int32_t ReadI32(const void* p)
{
    std::int32_t value = 0;
    std::memcpy(&value, p, sizeof(value));
    return value;
}

bool HasSubPrologue(const std::uint8_t* p)
{
    static const std::uint8_t prologue[15] = {
        0x40, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56,
        0x48, 0x81, 0xEC, 0x28, 0x04, 0x00, 0x00
    };

    return std::memcmp(p, prologue, sizeof(prologue)) == 0;
}

bool IsGuidBlock(const std::uint8_t* p)
{
    if (!(p[0] == 0x49 && p[1] == 0x3B && p[2] == 0x96))
        return false;
    if (ReadI32(p + 3) != static_cast<std::int32_t>(qword_7FF7FC606770))
        return false;
    if (!(p[7] == 0x75 && p[8] == 0x12))
        return false;
    if (!(p[9] == 0x48 && p[10] == 0x8B && p[11] == 0x50 && p[12] == 0x08))
        return false;
    if (!(p[13] == 0x49 && p[14] == 0x3B && p[15] == 0x96))
        return false;
    if (ReadI32(p + 16) != static_cast<std::int32_t>(qword_7FF7FC606778))
        return false;
    if (!(p[20] == 0x75 && p[21] == 0x05))
        return false;

    return true;
}

bool IsFlagGate(const std::uint8_t* p, std::uintptr_t instructionVa)
{
    if (!(p[0] == 0x44 && p[1] == 0x39 && p[2] == 0x2D))
        return false;
    if (!(p[7] == 0x0F && p[8] == 0x85))
        return false;

    const std::int32_t disp = ReadI32(p + 3);
    const std::uintptr_t target = instructionVa + 7 + disp;
    return target == g_base + dword_7FF7FC60676C;
}

bool WriteCode(void* dst, const void* src, std::size_t len)
{
    DWORD oldProtect = 0;
    DWORD ignored = 0;

    if (!VirtualProtect(dst, len, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        Log("VirtualProtect failed at %p (error %lu)", dst, GetLastError());
        return false;
    }

    std::memcpy(dst, src, len);
    VirtualProtect(dst, len, oldProtect, &ignored);
    FlushInstructionCache(GetCurrentProcess(), dst, len);
    return true;
}

// ---------------------------------------------------------------------------
// sub_7FF7FC3C7920 rewrite
// ---------------------------------------------------------------------------
bool PatchSub_7FF7FC3C7920()
{
    if (!g_textBegin || !g_textEnd)
        return false;

    // Cheap probe before reading the whole section on every poll. The code is
    // packed at first; this returns immediately until the compare block is
    // decrypted.
    {
        std::uint8_t probe[22]{};
        SIZE_T probeRead = 0;
        if (!ReadProcessMemory(GetCurrentProcess(),
                               reinterpret_cast<void*>(g_base + 0x158018),
                               probe, sizeof(probe), &probeRead) ||
            probeRead != sizeof(probe) ||
            !IsGuidBlock(probe))
        {
            return false;
        }
    }

    const std::size_t textSize =
        static_cast<std::size_t>(g_textEnd - g_textBegin);

    // Read the whole code section with ReadProcessMemory. This never faults on
    // a packed/guarded page; it just fails and the caller retries.
    auto* buffer = static_cast<std::uint8_t*>(
        VirtualAlloc(nullptr, textSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!buffer)
    {
        Log("VirtualAlloc(%zu) failed (%lu)", textSize, GetLastError());
        return false;
    }

    bool success = false;

    do
    {
        SIZE_T got = 0;
        if (!ReadProcessMemory(GetCurrentProcess(), g_textBegin, buffer, textSize, &got) ||
            got != textSize)
        {
            break; // not unpacked/readable yet
        }

        const std::uint8_t* bufferEnd = buffer + textSize;

        // ---- locate the two GUID compare blocks --------------------------
        const std::uint8_t* blocks[2] = {};
        int blockCount = 0;
        int foundBlocks = 0;

        for (const std::uint8_t* p = buffer; p + 22 <= bufferEnd; ++p)
        {
            if (!IsGuidBlock(p))
                continue;
            ++foundBlocks;
            if (blockCount < 2)
                blocks[blockCount++] = p;
        }

        if (foundBlocks == 0)
            break; // still packed, or not decrypted yet

        if (foundBlocks != 2)
        {
            Log("sub_7FF7FC3C7920: expected 2 GUID compare blocks, found %d", foundBlocks);
            break;
        }

        // ---- resolve the function start ----------------------------------
        const std::uint8_t* sub =
            reinterpret_cast<const std::uint8_t*>(g_base + sub_7FF7FC3C7920);
        const std::uint8_t* subBuffer = buffer + (sub - g_textBegin);

        if (subBuffer < buffer || subBuffer + 15 > bufferEnd)
        {
            Log("sub_7FF7FC3C7920: function RVA outside scanned section");
            break;
        }

        const std::uint8_t* functionStart = nullptr;

        if (HasSubPrologue(subBuffer))
        {
            functionStart = subBuffer;
        }
        else
        {
            Log("sub_7FF7FC3C7920: prologue mismatch at %p, walking back from compare site",
                static_cast<const void*>(sub));

            if (blocks[0] >= buffer + 15)
            {
                for (const std::uint8_t* p = blocks[0] - 15; p >= buffer; --p)
                {
                    if (blocks[0] - p > 0x2000)
                        break;
                    if (HasSubPrologue(p))
                    {
                        functionStart = p;
                        break;
                    }
                }
            }
        }

        if (!functionStart)
        {
            Log("sub_7FF7FC3C7920: function prologue not found, refusing to patch");
            break;
        }

        if (blocks[0] < functionStart ||
            blocks[1] > functionStart + 0x2000 ||
            functionStart + 0x2000 > bufferEnd)
        {
            Log("sub_7FF7FC3C7920: compare blocks outside function range, refusing to patch");
            break;
        }

        // ---- locate the old-header flag gate -----------------------------
        const std::uint8_t* flagGate = nullptr;
        int flagCount = 0;

        for (const std::uint8_t* p = functionStart;
             p + 13 <= functionStart + 0x2000;
             ++p)
        {
            const std::uintptr_t instructionVa =
                reinterpret_cast<std::uintptr_t>(g_textBegin + (p - buffer));
            if (!IsFlagGate(p, instructionVa))
                continue;
            ++flagCount;
            flagGate = p;
        }

        if (flagCount != 1)
        {
            Log("sub_7FF7FC3C7920: expected 1 flag gate, found %d", flagCount);
            break;
        }

        // ---- verify the exact bytes before writing -----------------------
        static const std::uint8_t qwordCmp[7] =
            { 0x49, 0x3B, 0x96, 0x70, 0x67, 0x39, 0x00 };
        static const std::uint8_t ffCmp[7] =
            { 0x49, 0x3B, 0x96, 0x78, 0x67, 0x39, 0x00 };

        for (int i = 0; i < 2; ++i)
        {
            if (std::memcmp(blocks[i] + 0, qwordCmp, 7) != 0 ||
                std::memcmp(blocks[i] + 13, ffCmp, 7) != 0)
            {
                Log("sub_7FF7FC3C7920: compare bytes changed before write, aborting");
                goto done;
            }
        }

        // ---- patch the live function -------------------------------------
        static const std::uint8_t cmpRdxRdx[7] =
            { 0x48, 0x3B, 0xD2, 0x90, 0x90, 0x90, 0x90 };
        static const std::uint8_t cmpR13R13[7] =
            { 0x45, 0x3B, 0xED, 0x90, 0x90, 0x90, 0x90 };

        std::uint8_t* liveBlock0 =
            const_cast<std::uint8_t*>(g_textBegin + (blocks[0] - buffer));
        std::uint8_t* liveBlock1 =
            const_cast<std::uint8_t*>(g_textBegin + (blocks[1] - buffer));
        std::uint8_t* liveFlag =
            const_cast<std::uint8_t*>(g_textBegin + (flagGate - buffer));

        Log("sub_7FF7FC3C7920 @ %p (RVA 0x%llX)",
            static_cast<const void*>(g_textBegin + (functionStart - buffer)),
            static_cast<unsigned long long>(
                (g_textBegin + (functionStart - buffer)) -
                reinterpret_cast<const std::uint8_t*>(g_base)));
        Log("  blocks: %p, %p", static_cast<void*>(liveBlock0), static_cast<void*>(liveBlock1));
        Log("  flag gate: %p", static_cast<void*>(liveFlag));

        bool ok = true;
        ok &= WriteCode(liveBlock0 + 0, cmpRdxRdx, 7);
        ok &= WriteCode(liveBlock0 + 13, cmpRdxRdx, 7);
        ok &= WriteCode(liveBlock1 + 0, cmpRdxRdx, 7);
        ok &= WriteCode(liveBlock1 + 13, cmpRdxRdx, 7);
        ok &= WriteCode(liveFlag + 0, cmpR13R13, 7);

        if (!ok)
        {
            Log("sub_7FF7FC3C7920: one or more patch writes failed");
            break;
        }

        // ---- read back through ReadProcessMemory -------------------------
        std::uint8_t check[7]{};
        SIZE_T checkRead = 0;
        bool verified = true;

        verified &= ReadProcessMemory(GetCurrentProcess(), liveBlock0 + 0, check, 7, &checkRead) &&
                    checkRead == 7 && std::memcmp(check, cmpRdxRdx, 7) == 0;
        verified &= ReadProcessMemory(GetCurrentProcess(), liveBlock0 + 13, check, 7, &checkRead) &&
                    checkRead == 7 && std::memcmp(check, cmpRdxRdx, 7) == 0;
        verified &= ReadProcessMemory(GetCurrentProcess(), liveBlock1 + 0, check, 7, &checkRead) &&
                    checkRead == 7 && std::memcmp(check, cmpRdxRdx, 7) == 0;
        verified &= ReadProcessMemory(GetCurrentProcess(), liveBlock1 + 13, check, 7, &checkRead) &&
                    checkRead == 7 && std::memcmp(check, cmpRdxRdx, 7) == 0;
        verified &= ReadProcessMemory(GetCurrentProcess(), liveFlag + 0, check, 7, &checkRead) &&
                    checkRead == 7 && std::memcmp(check, cmpR13R13, 7) == 0;

        if (!verified)
        {
            Log("sub_7FF7FC3C7920: read-back verification failed");
            break;
        }

        const auto guid =
            *reinterpret_cast<const std::uint64_t*>(g_base + qword_7FF7FC606770);
        Log("verified: GUID qword = 0x%016llX, comparisons patched",
            static_cast<unsigned long long>(guid));

        success = true;
    }
    while (false);

done:
    VirtualFree(buffer, 0, MEM_RELEASE);
    return success;
}

// ---------------------------------------------------------------------------
// sub_7FF7FC3C9A40 rewrite
//
//  This is the second lock reader (used when reading entries out of a .pkz,
//  which is the path tracks use). It gets the GUID through sub_7FF7FC3C9650
//  and compares it here:
//
//      48 3B 10              cmp rdx, [rax]
//      75 0E                 jnz fail
//      48 8B 51 08           mov rdx, [rcx+8]
//      48 3B 50 08           cmp rdx, [rax+8]
//      75 04                 jnz fail
//
//  The old-header path also rejects when sub_7FF7FC3C9660() (the reason
//  value) is non-zero.
// ---------------------------------------------------------------------------
bool PatchSub_7FF7FC3C9A40()
{
    if (!g_textBegin || !g_textEnd)
        return false;

    static const std::uint8_t cmpBlock[15] = {
        0x48, 0x3B, 0x10, 0x75, 0x0E, 0x48, 0x8B, 0x51,
        0x08, 0x48, 0x3B, 0x50, 0x08, 0x75, 0x04
    };

    // Cheap probe at the known compare site.
    {
        std::uint8_t probe[15]{};
        SIZE_T probeRead = 0;
        if (!ReadProcessMemory(GetCurrentProcess(),
                               reinterpret_cast<void*>(g_base + 0x159DD0),
                               probe, sizeof(probe), &probeRead) ||
            probeRead != sizeof(probe) ||
            std::memcmp(probe, cmpBlock, sizeof(probe)) != 0)
        {
            return false;
        }
    }

    const std::size_t textSize =
        static_cast<std::size_t>(g_textEnd - g_textBegin);

    auto* buffer = static_cast<std::uint8_t*>(
        VirtualAlloc(nullptr, textSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!buffer)
    {
        Log("VirtualAlloc(%zu) failed (%lu)", textSize, GetLastError());
        return false;
    }

    bool success = false;

    do
    {
        SIZE_T got = 0;
        if (!ReadProcessMemory(GetCurrentProcess(), g_textBegin, buffer, textSize, &got) ||
            got != textSize)
        {
            break;
        }

        const std::uint8_t* bufferEnd = buffer + textSize;
        const std::uint8_t* functionStart =
            buffer + (g_base + sub_7FF7FC3C9A40 - reinterpret_cast<std::uintptr_t>(g_textBegin));

        if (functionStart < buffer ||
            functionStart + sub_7FF7FC3C9A40_size > bufferEnd)
        {
            Log("sub_7FF7FC3C9A40: function RVA outside scanned section");
            break;
        }

        const std::uint8_t* functionEnd = functionStart + sub_7FF7FC3C9A40_size;

        // ---- two GUID compare blocks -------------------------------------
        const std::uint8_t* blocks[2] = {};
        int blockCount = 0;
        int foundBlocks = 0;

        for (const std::uint8_t* p = functionStart; p + 15 <= functionEnd; ++p)
        {
            if (std::memcmp(p, cmpBlock, 15) != 0)
                continue;
            ++foundBlocks;
            if (blockCount < 2)
                blocks[blockCount++] = p;
        }

        if (foundBlocks == 0)
            break; // not decrypted yet

        if (foundBlocks != 2)
        {
            Log("sub_7FF7FC3C9A40: expected 2 GUID compare blocks, found %d", foundBlocks);
            break;
        }

        // ---- old-header reason gate --------------------------------------
        const std::uint8_t* reasonGate = nullptr;
        int reasonCount = 0;

        for (const std::uint8_t* p = functionStart; p + 13 <= functionEnd; ++p)
        {
            if (p[0] != 0xE8 || p[5] != 0x85 || p[6] != 0xC0 ||
                p[7] != 0x0F || p[8] != 0x85)
            {
                continue;
            }

            const std::int32_t rel = ReadI32(p + 1);
            const std::uintptr_t callVa =
                reinterpret_cast<std::uintptr_t>(g_textBegin + (p - buffer));
            if (callVa + 5 + rel != g_base + sub_7FF7FC3C9660)
                continue;

            ++reasonCount;
            reasonGate = p;
        }

        if (reasonCount != 1)
        {
            Log("sub_7FF7FC3C9A40: expected 1 reason gate, found %d", reasonCount);
            break;
        }

        // ---- "GUID present" gate at function entry -----------------------
        //   call sub_7FF7FC3C9640
        //   test eax, eax
        //   jnz  continue
        const std::uint8_t* presentGate = nullptr;
        int presentCount = 0;

        for (const std::uint8_t* p = functionStart; p + 9 <= functionEnd; ++p)
        {
            if (p[0] != 0xE8 || p[5] != 0x85 || p[6] != 0xC0 ||
                p[7] != 0x75 || p[8] != 0x0A)
            {
                continue;
            }

            const std::int32_t rel = ReadI32(p + 1);
            const std::uintptr_t callVa =
                reinterpret_cast<std::uintptr_t>(g_textBegin + (p - buffer));
            if (callVa + 5 + rel != g_base + sub_7FF7FC3C9640)
                continue;

            ++presentCount;
            presentGate = p;
        }

        if (presentCount != 1)
        {
            Log("sub_7FF7FC3C9A40: expected 1 GUID-present gate, found %d", presentCount);
            break;
        }

        // ---- verify before writing ---------------------------------------
        if (std::memcmp(blocks[0], cmpBlock, 15) != 0 ||
            std::memcmp(blocks[1], cmpBlock, 15) != 0)
        {
            Log("sub_7FF7FC3C9A40: compare bytes changed before write, aborting");
            goto done;
        }

        static const std::uint8_t cmpSelf3[3] = { 0x48, 0x3B, 0xD2 };
        static const std::uint8_t cmpSelf4[4] = { 0x48, 0x3B, 0xD2, 0x90 };
        static const std::uint8_t nops6[6] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
        static const std::uint8_t jmpShort[2] = { 0xEB, 0x0A };

        Log("sub_7FF7FC3C9A40 @ %p (RVA 0x%llX)",
            static_cast<const void*>(g_textBegin + (functionStart - buffer)),
            static_cast<unsigned long long>(sub_7FF7FC3C9A40));

        bool ok = true;
        for (int i = 0; i < 2; ++i)
        {
            auto* live = const_cast<std::uint8_t*>(
                g_textBegin + (blocks[i] - buffer));
            ok &= WriteCode(live + 0, cmpSelf3, 3);
            ok &= WriteCode(live + 9, cmpSelf4, 4);
        }

        auto* liveGate = const_cast<std::uint8_t*>(
            g_textBegin + (reasonGate - buffer));
        ok &= WriteCode(liveGate + 7, nops6, 6);

        auto* livePresent = const_cast<std::uint8_t*>(
            g_textBegin + (presentGate - buffer));
        ok &= WriteCode(livePresent + 7, jmpShort, 2);

        if (!ok)
        {
            Log("sub_7FF7FC3C9A40: one or more patch writes failed");
            break;
        }

        // ---- read back ----------------------------------------------------
        std::uint8_t check[15]{};
        SIZE_T checkRead = 0;
        bool verified = true;

        for (int i = 0; i < 2; ++i)
        {
            auto* live = const_cast<std::uint8_t*>(
                g_textBegin + (blocks[i] - buffer));
            verified &= ReadProcessMemory(GetCurrentProcess(), live + 0, check, 3, &checkRead) &&
                        checkRead == 3 && std::memcmp(check, cmpSelf3, 3) == 0;
            verified &= ReadProcessMemory(GetCurrentProcess(), live + 9, check, 4, &checkRead) &&
                        checkRead == 4 && std::memcmp(check, cmpSelf4, 4) == 0;
        }
        verified &= ReadProcessMemory(GetCurrentProcess(), liveGate + 7, check, 6, &checkRead) &&
                    checkRead == 6 && std::memcmp(check, nops6, 6) == 0;
        verified &= ReadProcessMemory(GetCurrentProcess(), livePresent + 7, check, 2, &checkRead) &&
                    checkRead == 2 && std::memcmp(check, jmpShort, 2) == 0;

        if (!verified)
        {
            Log("sub_7FF7FC3C9A40: read-back verification failed");
            break;
        }

        Log("verified: sub_7FF7FC3C9A40 GUID checks patched");
        success = true;
    }
    while (false);

done:
    VirtualFree(buffer, 0, MEM_RELEASE);
    return success;
}

// ---------------------------------------------------------------------------
// track list reload
//
//  FrostMod re-runs the game's own track-list loader (RVA 0x2460) on the
//  render/UI thread. We do the same through the game's window procedure, so
//  the call happens on the thread that owns the track list.
// ---------------------------------------------------------------------------
LRESULT CALLBACK GameWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (g_reloadMessage && msg == g_reloadMessage)
    {
        if (!g_trackReloadDone.exchange(true))
        {
            const int before =
                *reinterpret_cast<volatile int*>(g_base + dword_7FF7FD1B3298);
            Log("track list: reloading from disk (count before = %d)...", before);

            using LoaderSC_t = std::int64_t(__fastcall*)(std::int64_t, std::int64_t);
            auto loader = reinterpret_cast<LoaderSC_t>(g_base + sub_7FF7FC272460);

            __try
            {
                loader(0, 0);

                const int after =
                    *reinterpret_cast<volatile int*>(g_base + dword_7FF7FD1B3298);
                Log("track list: reloaded (count after = %d)", after);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                Log("track list: reload faulted");
            }
        }
        return 0;
    }

    if (msg == WM_KEYDOWN && wParam == VK_F9)
    {
        g_trackReloadDone.store(false);
        if (g_reloadMessage)
            PostMessageW(hwnd, g_reloadMessage, 0, 0);
        Log("track list: F9 pressed, reload requested");
        return 0;
    }

    if (g_originalWndProc)
        return CallWindowProcW(g_originalWndProc, hwnd, msg, wParam, lParam);

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

void ScheduleTrackReload()
{
    if (!g_reloadMessage)
        g_reloadMessage = RegisterWindowMessageW(L"MxBikesGuidBypassReload");

    for (int i = 0; i < 600 && !g_gameWindow; ++i) // up to 60 s for the window
    {
        g_gameWindow = FindWindowW(L"Core Window Class", nullptr);
        if (!g_gameWindow)
            Sleep(100);
    }

    if (!g_gameWindow)
    {
        Log("track list: game window not found");
        return;
    }

    g_originalWndProc = reinterpret_cast<WNDPROC>(
        SetWindowLongPtrW(g_gameWindow, GWLP_WNDPROC,
                          reinterpret_cast<LONG_PTR>(&GameWndProc)));

    if (!g_originalWndProc)
    {
        Log("track list: SetWindowLongPtr failed (%lu)", GetLastError());
        return;
    }

    Log("track list: waiting for the game's initial scan...");

    for (int i = 0; i < 600; ++i) // up to 60 s
    {
        const int count = *reinterpret_cast<volatile int*>(g_base + dword_7FF7FD1B3298);
        const std::uintptr_t list =
            *reinterpret_cast<volatile std::uintptr_t*>(g_base + qword_7FF7FD30DE98);

        if (count > 0 && list)
        {
            Sleep(2000);
            break;
        }
        Sleep(100);
    }

    PostMessageW(g_gameWindow, g_reloadMessage, 0, 0);
    Log("track list: reload requested");
}

// ---------------------------------------------------------------------------
// entry thread
// ---------------------------------------------------------------------------
DWORD WINAPI InitThread(LPVOID)
{
    wchar_t dataPath[MAX_PATH]{};
    wchar_t* appData = nullptr;
    std::size_t appDataLength = 0;

    if (_wdupenv_s(&appData, &appDataLength, L"LOCALAPPDATA") == 0 && appData)
    {
        wcscpy_s(dataPath, appData);
        std::free(appData);
        wcscat_s(dataPath, L"\\MxBikesGuidBypass");
        CreateDirectoryW(dataPath, nullptr);
    }
    else
    {
        GetModuleFileNameW(g_self, dataPath, MAX_PATH);
        wchar_t* slash = std::wcsrchr(dataPath, L'\\');
        if (slash)
            *slash = L'\0';
    }

    wchar_t logPath[MAX_PATH + 32]{};
    swprintf_s(logPath, L"%s\\MxBikesGuidBypass.log", dataPath);

    wchar_t iniPath[MAX_PATH + 32]{};
    swprintf_s(iniPath, L"%s\\MxBikesGuidBypass.ini", dataPath);
    g_logEnabled = GetPrivateProfileIntW(L"General", L"Log", 1, iniPath) != 0;

    if (g_logEnabled)
        g_log = _wfsopen(logPath, L"a", _SH_DENYNO);

    Log("=== MxBikesGuidBypass starting ===");

    g_base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
    if (!g_base)
    {
        Log("GetModuleHandle(NULL) failed (%lu)", GetLastError());
        return 0;
    }

    Log("module base = 0x%llX", static_cast<unsigned long long>(g_base));

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(g_base);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        Log("invalid DOS header");
        return 0;
    }

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(g_base + dos->e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        Log("invalid NT header / not x64");
        return 0;
    }

    const auto* sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec)
    {
        const std::uintptr_t start = sec->VirtualAddress;
        const std::uintptr_t size =
            sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;

        if (sub_7FF7FC3C7920 >= start && sub_7FF7FC3C7920 < start + size)
        {
            g_textBegin = reinterpret_cast<const std::uint8_t*>(g_base + start);
            g_textEnd = g_textBegin + size;
            Log("scanning section %s: RVA 0x%llX - 0x%llX",
                reinterpret_cast<const char*>(sec->Name),
                static_cast<unsigned long long>(start),
                static_cast<unsigned long long>(start + size));
            break;
        }
    }

    if (!g_textBegin)
    {
        Log("could not find the section containing sub_7FF7FC3C7920");
        return 0;
    }

    for (int attempt = 0; attempt < 30000; ++attempt) // ~5 minutes at 10 ms
    {
        static bool patched7920 = false;
        static bool patched9A40 = false;

        if (!patched7920)
            patched7920 = PatchSub_7FF7FC3C7920();
        if (!patched9A40)
            patched9A40 = PatchSub_7FF7FC3C9A40();

        if (patched7920 && patched9A40)
        {
            Log("ready: sub_7FF7FC3C7920 and sub_7FF7FC3C9A40 are patched");
            ScheduleTrackReload();
            return 0;
        }

        // Poll fast right after injection; the cheap probe makes this cheap
        // while the image is still packed.
        Sleep(10);
    }

    Log("gave up: sub_7FF7FC3C7920 / sub_7FF7FC3C9A40 were not both found");
    return 0;
}

} // namespace

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        g_self = module;
        DisableThreadLibraryCalls(module);

        HANDLE thread = CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr);
        if (thread)
            CloseHandle(thread);
    }
    return TRUE;
}
