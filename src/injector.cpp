
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <iostream>
#include <cstring>

#define NT_SUCCESS(s)                ((NTSTATUS)(s) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH  ((NTSTATUS)0xC0000004)
#define SystemHandleInformation      16
#define SEC_IMAGE                    0x1000000
#define SEC_COMMIT                   0x8000000

#ifndef CFG_CALL_TARGET_VALID
#define CFG_CALL_TARGET_VALID 0x1
#endif

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR  ObjectTypeIndex;
    UCHAR  HandleAttributes;
    USHORT HandleValue;
    PVOID  Object;
    ULONG  GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION;

// TP_DIRECT_INJECT — 72 bytes written to code cave (IDA @ 0x140005A83)
struct TP_DIRECT_INJECT {
    ULONG64 TaskQueueEntry;
    ULONG64 PoolRef;
    ULONG64 Pad10[2];
    ULONG64 Pad20[2];
    ULONG64 CleanupGroup;
    PVOID   Callback;   // +0x38 — only non-zero field
    PVOID   Context;
};
static_assert(sizeof(TP_DIRECT_INJECT) == 0x48);

// LOADER_CONTEXT — 96 bytes (IDA @ 0x140005DC9)
struct LOADER_CONTEXT {
    PVOID   ImageBase;
    PVOID   LoadLibraryA;
    PVOID   GetProcAddress;
    PVOID   RtlAddFunctionTable;
    PVOID   EntryPoint;
    ULONG64 ImportDirRVA;
    ULONG64 ImportDirSize;
    ULONG64 ExceptionDirRVA;
    ULONG64 ExceptionDirSize;
    ULONG64 TLSDirRVA;
    ULONG64 TLSDirSize;
    DWORD   StageProgress;
    DWORD   Pad;
};
static_assert(sizeof(LOADER_CONTEXT) == 0x60);

typedef NTSTATUS(NTAPI* pfnNtCreateSection)            (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS(NTAPI* pfnNtMapViewOfSection)          (HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
typedef NTSTATUS(NTAPI* pfnNtUnmapViewOfSection)        (HANDLE, PVOID);
typedef NTSTATUS(NTAPI* pfnNtWriteVirtualMemory)        (HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* pfnNtQuerySystemInformation)    (ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* pfnNtDuplicateObject)           (HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
typedef NTSTATUS(NTAPI* pfnNtQueryObject)               (HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* pfnNtSetIoCompletion)           (HANDLE, PVOID, PVOID, NTSTATUS, ULONG_PTR);
typedef BOOL(WINAPI* pfnSetProcessValidCallTargets) (HANDLE, PVOID, SIZE_T, ULONG, CFG_CALL_TARGET_INFO*);

static pfnNtCreateSection            g_NtCreateSection;
static pfnNtMapViewOfSection         g_NtMapViewOfSection;
static pfnNtUnmapViewOfSection       g_NtUnmapViewOfSection;
static pfnNtWriteVirtualMemory       g_NtWriteVirtualMemory;
static pfnNtQuerySystemInformation   g_NtQuerySystemInformation;
static pfnNtDuplicateObject          g_NtDuplicateObject;
static pfnNtQueryObject              g_NtQueryObject;
static pfnNtSetIoCompletion          g_NtSetIoCompletion;
static pfnSetProcessValidCallTargets g_SetProcessValidCallTargets;

static void ResolveAPIs() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
#define R(mod, name) g_##name = (pfn##name)GetProcAddress(mod, #name)
    R(hNtdll, NtCreateSection);
    R(hNtdll, NtMapViewOfSection);
    R(hNtdll, NtUnmapViewOfSection);
    R(hNtdll, NtWriteVirtualMemory);
    R(hNtdll, NtQuerySystemInformation);
    R(hNtdll, NtDuplicateObject);
    R(hNtdll, NtQueryObject);
    R(hNtdll, NtSetIoCompletion);
    R(hKernel32, SetProcessValidCallTargets);
#undef R
}

// sub_14000BAA4 — 48-bit PRNG seed, called from start() before main()
static void SeedPRNG() {
    FILETIME ft = {};
    GetSystemTimeAsFileTime(&ft);
    ULONG64 seed = *(ULONG64*)&ft;
    seed ^= GetCurrentThreadId();
    seed ^= GetCurrentProcessId();
    LARGE_INTEGER pc;
    QueryPerformanceCounter(&pc);
    seed ^= (ULONG64)(ULONG_PTR)&seed;
    seed ^= pc.QuadPart ^ ((ULONG64)pc.LowPart << 32);
    seed &= 0x0000FFFFFFFFFFFFull;
    if (seed == 0x2B992DDFA232ull) seed = 0x2B992DDFA233ull;
    srand((unsigned)seed);
}

// sub_1400042E0 — find a System32 DLL whose SEC_IMAGE view is exactly 64 KB
static char* FindRandomSystem32DLL() {
    const int SLOT = MAX_PATH, CAP = 64;
    char* list = (char*)malloc((size_t)SLOT * CAP);
    int   n = 0, cap = CAP;
    if (!list) return nullptr;

    WIN32_FIND_DATAA ffd;
    HANDLE hFind = FindFirstFileA("C:\\Windows\\System32\\*.dll", &ffd);
    if (hFind == INVALID_HANDLE_VALUE) { free(list); return nullptr; }

    do {
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (ffd.nFileSizeHigh || ffd.nFileSizeLow > 0xFFFF)  continue;

        char path[MAX_PATH];
        snprintf(path, MAX_PATH, "C:\\Windows\\System32\\%s", ffd.cFileName);

        HANDLE hFile = CreateFileA(path, GENERIC_READ | GENERIC_EXECUTE,
            FILE_SHARE_READ, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) continue;

        HANDLE hSec = nullptr;
        NTSTATUS st = g_NtCreateSection(&hSec, SECTION_ALL_ACCESS, nullptr, nullptr,
            PAGE_READONLY, SEC_IMAGE, hFile);
        CloseHandle(hFile);
        if (!NT_SUCCESS(st)) continue;

        PVOID  base = nullptr;
        SIZE_T vsz = 0;
        st = g_NtMapViewOfSection(hSec, GetCurrentProcess(), &base,
            0, 0, nullptr, &vsz, 2, 0, PAGE_READONLY);
        if (NT_SUCCESS(st)) {
            if (vsz == 0x10000) {
                if (n == cap) { cap *= 2; list = (char*)realloc(list, (size_t)SLOT * cap); }
                strncpy_s(list + (size_t)SLOT * n++, MAX_PATH, path, _TRUNCATE);
            }
            g_NtUnmapViewOfSection(GetCurrentProcess(), base);
        }
        CloseHandle(hSec);
    } while (FindNextFileA(hFind, &ffd));
    FindClose(hFind);

    if (!n) { free(list); return nullptr; }
    char* result = _strdup(list + (size_t)SLOT * (rand() % n));
    free(list);
    return result;
}

// Reads "module.dll" from the current directory
static PBYTE LoadPayloadFromDisk(SIZE_T& outSize) {
    outSize = 0;
    HANDLE hFile = CreateFileA("Module.dll", GENERIC_READ | GENERIC_EXECUTE,
        FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return nullptr;

    LARGE_INTEGER sz;
    if (!GetFileSizeEx(hFile, &sz) || !sz.QuadPart) { CloseHandle(hFile); return nullptr; }

    PBYTE buf = (PBYTE)malloc((SIZE_T)sz.QuadPart);
    if (!buf) { CloseHandle(hFile); return nullptr; }

    DWORD read = 0;
    if (!ReadFile(hFile, buf, (DWORD)sz.QuadPart, &read, nullptr) || read != sz.QuadPart) {
        free(buf); CloseHandle(hFile); return nullptr;
    }
    CloseHandle(hFile);
    outSize = (SIZE_T)sz.QuadPart;
    return buf;
}

// Base relocation — IMAGE_REL_BASED_DIR64 only (IDA @ 0x140005529)
static void ApplyRelocations(PBYTE buf, ULONG64 oldBase, ULONG64 newBase) {
    auto* pNt = (PIMAGE_NT_HEADERS64)(buf + ((PIMAGE_DOS_HEADER)buf)->e_lfanew);
    auto& dir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!dir.VirtualAddress || !dir.Size) return;

    INT64 delta = (INT64)(newBase - oldBase);
    if (!delta) return;

    auto* blk = (PIMAGE_BASE_RELOCATION)(buf + dir.VirtualAddress);
    PBYTE end = buf + dir.VirtualAddress + dir.Size;
    while ((PBYTE)blk < end && blk->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
        DWORD cnt = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        PWORD ent = (PWORD)((PBYTE)blk + sizeof(IMAGE_BASE_RELOCATION));
        for (DWORD i = 0; i < cnt; i++) {
            if ((ent[i] & 0xF000) == (IMAGE_REL_BASED_DIR64 << 12))
                *(ULONG64*)(buf + blk->VirtualAddress + (ent[i] & 0xFFF)) += delta;
        }
        blk = (PIMAGE_BASE_RELOCATION)((PBYTE)blk + blk->SizeOfBlock);
    }
}

// Phase B — module stomp (IDA @ 0x140005229)
static ULONG64 MapAndStompPayload(HANDLE hProcess, PBYTE payloadBuf,
    SIZE_T /*payloadSize*/, PIMAGE_NT_HEADERS64 pNt)
{
    const SIZE_T CHUNK = 0x10000;
    SIZE_T imgSz = pNt->OptionalHeader.SizeOfImage;
    SIZE_T aligned = (imgSz + CHUNK - 1) & ~(CHUNK - 1);
    SIZE_T nChunks = aligned / CHUNK;

    MEMORY_BASIC_INFORMATION mbi = {};
    ULONG64 base = 0;
    for (PBYTE p = (PBYTE)0x10000; VirtualQueryEx(hProcess, p, &mbi, sizeof(mbi));
        p = (PBYTE)mbi.BaseAddress + mbi.RegionSize) {
        if (mbi.State != MEM_FREE || mbi.RegionSize < aligned) continue;
        ULONG64 a = ((ULONG64)mbi.BaseAddress + 0xFFFF) & ~(ULONG64)0xFFFF;
        if (a + aligned <= (ULONG64)mbi.BaseAddress + mbi.RegionSize) { base = a; break; }
    }
    if (!base) { std::cout << " Failed to find free region" << std::endl; return 0; }

    char* dllPath = FindRandomSystem32DLL();
    if (!dllPath) { std::cout << " Failed to find dummy DLL" << std::endl; return 0; }

    HANDLE hFile = CreateFileA(dllPath, GENERIC_READ | GENERIC_EXECUTE,
        FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    free(dllPath);
    if (hFile == INVALID_HANDLE_VALUE) { std::cout << " Failed to open dummy DLL" << std::endl; return 0; }

    for (SIZE_T i = 0; i < nChunks; i++) {
        HANDLE hSec = nullptr;
        if (NT_SUCCESS(g_NtCreateSection(&hSec, SECTION_ALL_ACCESS, nullptr, nullptr,
            PAGE_READONLY, SEC_IMAGE, hFile))) {
            PVOID  addr = (PVOID)(base + i * CHUNK);
            SIZE_T vsz = 0;
            if (NT_SUCCESS(g_NtMapViewOfSection(hSec, hProcess, &addr,
                0, 0, nullptr, &vsz, 2, 0, PAGE_READONLY))) {
                DWORD old = 0;
                VirtualProtectEx(hProcess, addr, CHUNK, PAGE_EXECUTE_READWRITE, &old);
            }
            CloseHandle(hSec);
        }
    }
    CloseHandle(hFile);

    PBYTE zeros = (PBYTE)calloc(aligned, 1);
    g_NtWriteVirtualMemory(hProcess, (PVOID)base, zeros, aligned, nullptr);
    free(zeros);

    PBYTE img = (PBYTE)calloc(aligned, 1);
    memcpy(img, payloadBuf, pNt->OptionalHeader.SizeOfHeaders);

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(pNt);
    for (WORD s = 0; s < pNt->FileHeader.NumberOfSections; s++) {
        if (!sec[s].SizeOfRawData) continue;
        memcpy(img + sec[s].VirtualAddress,
            payloadBuf + sec[s].PointerToRawData,
            sec[s].SizeOfRawData);
    }

    ApplyRelocations(img, pNt->OptionalHeader.ImageBase, base);

    NTSTATUS st = g_NtWriteVirtualMemory(hProcess, (PVOID)base, img, imgSz, nullptr);
    free(img);
    if (!NT_SUCCESS(st)) {
        std::cout << "NtWriteVirtualMemory failed: 0x" << std::hex << st << std::endl;
        return 0;
    }

    for (WORD s = 0; s < pNt->FileHeader.NumberOfSections; s++) {
        DWORD f = sec[s].Characteristics;
        DWORD prot = (f & IMAGE_SCN_MEM_EXECUTE) ? PAGE_EXECUTE_READ
            : (f & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE
            : PAGE_READONLY;
        DWORD old = 0;
        VirtualProtectEx(hProcess, (PVOID)(base + sec[s].VirtualAddress),
            sec[s].Misc.VirtualSize, prot, &old);
    }
    return base;
}

// sub_140005DA0 — 1009 bytes, extracted via IDA MCP get_bytes.
// Compiled without /GS — no __security_cookie in prologue.
// Stages: 1=init, 2=imports, 3=TLS guard, 4=TLS+SEH, 5=DllMain, 6=done
static const BYTE g_Loader[] = {
    0x48,0x89,0x4C,0x24,0x08,0x48,0x81,0xEC,0xD8,0x00,0x00,0x00,0x48,0x83,0xBC,0x24,
    0xE0,0x00,0x00,0x00,0x00,0x75,0x0A,0xB8,0x01,0x00,0x00,0x00,0xE9,0xC8,0x03,0x00,
    0x00,0x48,0x8B,0x84,0x24,0xE0,0x00,0x00,0x00,0xC7,0x40,0x58,0x01,0x00,0x00,0x00,
    0x48,0x8B,0x84,0x24,0xE0,0x00,0x00,0x00,0x48,0x8B,0x40,0x08,0x48,0x89,0x44,0x24,
    0x60,0x48,0x8B,0x84,0x24,0xE0,0x00,0x00,0x00,0x48,0x8B,0x40,0x10,0x48,0x89,0x44,
    0x24,0x58,0x48,0x8B,0x84,0x24,0xE0,0x00,0x00,0x00,0x48,0x8B,0x00,0x48,0x89,0x44,
    0x24,0x20,0x48,0x8B,0x84,0x24,0xE0,0x00,0x00,0x00,0xC7,0x40,0x58,0x02,0x00,0x00,
    0x00,0x48,0x8B,0x84,0x24,0xE0,0x00,0x00,0x00,0x48,0x83,0x78,0x28,0x00,0x0F,0x84,
    0xA1,0x01,0x00,0x00,0x48,0x8B,0x84,0x24,0xE0,0x00,0x00,0x00,0x48,0x83,0x78,0x30,
    0x00,0x0F,0x84,0x8E,0x01,0x00,0x00,0x48,0x8B,0x84,0x24,0xE0,0x00,0x00,0x00,0x48,
    0x8B,0x40,0x28,0x48,0x8B,0x4C,0x24,0x20,0x48,0x03,0xC8,0x48,0x8B,0xC1,0x48,0x89,
    0x44,0x24,0x28,0x48,0x8B,0x44,0x24,0x28,0x83,0x78,0x0C,0x00,0x0F,0x84,0x63,0x01,
    0x00,0x00,0x48,0x8B,0x44,0x24,0x28,0x8B,0x40,0x0C,0x48,0x8B,0x4C,0x24,0x20,0x48,
    0x03,0xC8,0x48,0x8B,0xC1,0x48,0x89,0x44,0x24,0x68,0x48,0x8B,0x44,0x24,0x60,0x48,
    0x89,0x44,0x24,0x70,0x48,0x8B,0x4C,0x24,0x68,0xFF,0x54,0x24,0x70,0x48,0x89,0x44,
    0x24,0x50,0x48,0x83,0x7C,0x24,0x50,0x00,0x0F,0x84,0x14,0x01,0x00,0x00,0x48,0x8B,
    0x44,0x24,0x28,0x83,0x38,0x00,0x74,0x0D,0x48,0x8B,0x44,0x24,0x28,0x8B,0x00,0x89,
    0x44,0x24,0x38,0xEB,0x0C,0x48,0x8B,0x44,0x24,0x28,0x8B,0x40,0x10,0x89,0x44,0x24,
    0x38,0x8B,0x44,0x24,0x38,0x48,0x8B,0x4C,0x24,0x20,0x48,0x03,0xC8,0x48,0x8B,0xC1,
    0x48,0x89,0x44,0x24,0x30,0x48,0x8B,0x44,0x24,0x28,0x8B,0x40,0x10,0x48,0x8B,0x4C,
    0x24,0x20,0x48,0x03,0xC8,0x48,0x8B,0xC1,0x48,0x89,0x44,0x24,0x48,0xEB,0x1C,0x48,
    0x8B,0x44,0x24,0x30,0x48,0x83,0xC0,0x08,0x48,0x89,0x44,0x24,0x30,0x48,0x8B,0x44,
    0x24,0x48,0x48,0x83,0xC0,0x08,0x48,0x89,0x44,0x24,0x48,0x48,0x8B,0x44,0x24,0x30,
    0x48,0x83,0x38,0x00,0x0F,0x84,0x98,0x00,0x00,0x00,0x48,0x8B,0x44,0x24,0x30,0x48,
    0xB9,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80,0x48,0x8B,0x00,0x48,0x23,0xC1,0x48,
    0x85,0xC0,0x74,0x2E,0x48,0x8B,0x44,0x24,0x58,0x48,0x89,0x44,0x24,0x78,0x48,0x8B,
    0x44,0x24,0x30,0x48,0x8B,0x00,0x48,0x25,0xFF,0xFF,0x00,0x00,0x48,0x8B,0xD0,0x48,
    0x8B,0x4C,0x24,0x50,0xFF,0x54,0x24,0x78,0x48,0x8B,0x4C,0x24,0x48,0x48,0x89,0x01,
    0xEB,0x4B,0x48,0x8B,0x44,0x24,0x30,0x48,0x8B,0x00,0x48,0x8B,0x4C,0x24,0x20,0x48,
    0x03,0xC8,0x48,0x8B,0xC1,0x48,0x89,0x84,0x24,0x80,0x00,0x00,0x00,0x48,0x8B,0x44,
    0x24,0x58,0x48,0x89,0x84,0x24,0x88,0x00,0x00,0x00,0x48,0x8B,0x84,0x24,0x80,0x00,
    0x00,0x00,0x48,0x83,0xC0,0x02,0x48,0x8B,0xD0,0x48,0x8B,0x4C,0x24,0x50,0xFF,0x94,
    0x24,0x88,0x00,0x00,0x00,0x48,0x8B,0x4C,0x24,0x48,0x48,0x89,0x01,0xE9,0x3D,0xFF,
    0xFF,0xFF,0x48,0x8B,0x44,0x24,0x28,0x48,0x83,0xC0,0x14,0x48,0x89,0x44,0x24,0x28,
    0xE9,0x8E,0xFE,0xFF,0xFF,0x48,0x8B,0x84,0x24,0xE0,0x00,0x00,0x00,0xC7,0x40,0x58,
    0x03,0x00,0x00,0x00,0x48,0x8B,0x84,0x24,0xE0,0x00,0x00,0x00,0x48,0x83,0x78,0x48,
    0x00,0x0F,0x84,0xA2,0x01,0x00,0x00,0x48,0x8B,0x84,0x24,0xE0,0x00,0x00,0x00,0x48,
    0x83,0x78,0x50,0x00,0x0F,0x84,0x8F,0x01,0x00,0x00,0x48,0x8B,0x84,0x24,0xE0,0x00,
    0x00,0x00,0x48,0x8B,0x40,0x48,0x48,0x8B,0x4C,0x24,0x20,0x48,0x03,0xC8,0x48,0x8B,
    0xC1,0x48,0x89,0x84,0x24,0x90,0x00,0x00,0x00,0x48,0x8B,0x84,0x24,0x90,0x00,0x00,
    0x00,0x48,0x8B,0x40,0x18,0x48,0x89,0x44,0x24,0x40,0x48,0x83,0x7C,0x24,0x40,0x00,
    0x74,0x3F,0x48,0x8B,0x44,0x24,0x40,0x48,0x83,0x38,0x00,0x74,0x34,0x48,0x8B,0x44,
    0x24,0x40,0x48,0x8B,0x00,0x48,0x89,0x84,0x24,0x98,0x00,0x00,0x00,0x45,0x33,0xC0,
    0xBA,0x01,0x00,0x00,0x00,0x48,0x8B,0x4C,0x24,0x20,0xFF,0x94,0x24,0x98,0x00,0x00,
    0x00,0x48,0x8B,0x44,0x24,0x40,0x48,0x83,0xC0,0x08,0x48,0x89,0x44,0x24,0x40,0xEB,
    0xC1,0x48,0x8B,0x84,0x24,0xE0,0x00,0x00,0x00,0xC7,0x40,0x58,0x04,0x00,0x00,0x00,
    0x48,0x8B,0x84,0x24,0xE0,0x00,0x00,0x00,0x48,0x83,0x78,0x18,0x00,0x0F,0x84,0x8E,
    0x00,0x00,0x00,0x48,0x8B,0x84,0x24,0xE0,0x00,0x00,0x00,0x48,0x83,0x78,0x38,0x00,
    0x74,0x7F,0x48,0x8B,0x84,0x24,0xE0,0x00,0x00,0x00,0x48,0x83,0x78,0x40,0x00,0x74,
    0x70,0x48,0x8B,0x84,0x24,0xE0,0x00,0x00,0x00,0x48,0x8B,0x40,0x18,0x48,0x89,0x84,
    0x24,0xA0,0x00,0x00,0x00,0x48,0x8B,0x84,0x24,0xE0,0x00,0x00,0x00,0x48,0x8B,0x40,
    0x38,0x48,0x8B,0x4C,0x24,0x20,0x48,0x03,0xC8,0x48,0x8B,0xC1,0x48,0x89,0x84,0x24,
    0xA8,0x00,0x00,0x00,0x48,0x8B,0x84,0x24,0xA0,0x00,0x00,0x00,0x48,0x89,0x84,0x24,
    0xB0,0x00,0x00,0x00,0x33,0xD2,0x48,0x8B,0x84,0x24,0xE0,0x00,0x00,0x00,0x48,0x8B,
    0x40,0x40,0xB9,0x0C,0x00,0x00,0x00,0x48,0xF7,0xF1,0x4C,0x8B,0x44,0x24,0x20,0x8B,
    0xD0,0x48,0x8B,0x8C,0x24,0xA8,0x00,0x00,0x00,0xFF,0x94,0x24,0xB0,0x00,0x00,0x00,
    0x90,0x48,0x8B,0x84,0x24,0xE0,0x00,0x00,0x00,0xC7,0x40,0x58,0x05,0x00,0x00,0x00,
    0x48,0x8B,0x84,0x24,0xE0,0x00,0x00,0x00,0x48,0x83,0x78,0x20,0x00,0x74,0x39,0x48,
    0x8B,0x84,0x24,0xE0,0x00,0x00,0x00,0x48,0x8B,0x40,0x20,0x48,0x89,0x84,0x24,0xB8,
    0x00,0x00,0x00,0x48,0x8B,0x84,0x24,0xB8,0x00,0x00,0x00,0x48,0x89,0x84,0x24,0xC0,
    0x00,0x00,0x00,0x45,0x33,0xC0,0xBA,0x01,0x00,0x00,0x00,0x48,0x8B,0x4C,0x24,0x20,
    0xFF,0x94,0x24,0xC0,0x00,0x00,0x00,0x90,0x48,0x8B,0x84,0x24,0xE0,0x00,0x00,0x00,
    0xC7,0x40,0x58,0x06,0x00,0x00,0x00,0x33,0xC0,0x48,0x81,0xC4,0xD8,0x00,0x00,0x00,
    0xC3
};

// Phase C — shared SEC_COMMIT section: [loader | LOADER_CONTEXT | trampoline]
// Trampoline (22 bytes @ IDA 0x1400059C5): MOV RAX,loader; MOV RCX,ctx; JMP RAX
static bool BuildLoaderSection(HANDLE hProcess, ULONG64 payloadBase,
    PIMAGE_NT_HEADERS64 pNt, PVOID* pTrampoline)
{
    const SIZE_T LSIZ = sizeof(g_Loader);
    const SIZE_T LALIGN = (LSIZ + 15) & ~(SIZE_T)15;
    const SIZE_T SECSZ = LALIGN + sizeof(LOADER_CONTEXT) + 22 + 352;

    LARGE_INTEGER sz = { (LONGLONG)SECSZ };
    HANDLE hSec = nullptr;
    NTSTATUS st = g_NtCreateSection(&hSec, SECTION_ALL_ACCESS, nullptr, &sz,
        PAGE_EXECUTE_READWRITE, SEC_COMMIT, nullptr);
    if (!NT_SUCCESS(st)) return false;

    PVOID  secBase = nullptr;
    SIZE_T vsz = SECSZ;
    st = g_NtMapViewOfSection(hSec, hProcess, &secBase, 0, 0, nullptr,
        &vsz, 2, 0, PAGE_EXECUTE_READWRITE);
    CloseHandle(hSec);
    if (!NT_SUCCESS(st)) return false;

    PBYTE loaderAddr = (PBYTE)secBase;
    PBYTE ctxAddr = loaderAddr + LALIGN;
    PBYTE tramAddr = ctxAddr + sizeof(LOADER_CONTEXT);

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");

    LOADER_CONTEXT ctx = {};
    ctx.ImageBase = (PVOID)payloadBase;
    ctx.LoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
    ctx.GetProcAddress = GetProcAddress(hKernel32, "GetProcAddress");
    ctx.RtlAddFunctionTable = GetProcAddress(hNtdll, "RtlAddFunctionTable");

    DWORD ep = pNt->OptionalHeader.AddressOfEntryPoint;
    ctx.EntryPoint = ep ? (PVOID)(payloadBase + ep) : nullptr;

    auto& imp = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    auto& exc = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    auto& tls = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    ctx.ImportDirRVA = imp.VirtualAddress; ctx.ImportDirSize = imp.Size;
    ctx.ExceptionDirRVA = exc.VirtualAddress; ctx.ExceptionDirSize = exc.Size;
    ctx.TLSDirRVA = tls.VirtualAddress; ctx.TLSDirSize = tls.Size;

    BYTE tramp[22];
    tramp[0] = 0x48; tramp[1] = 0xB8; memcpy(tramp + 2, &loaderAddr, 8);
    tramp[10] = 0x48; tramp[11] = 0xB9; memcpy(tramp + 12, &ctxAddr, 8);
    tramp[20] = 0xFF; tramp[21] = 0xE0;

    g_NtWriteVirtualMemory(hProcess, loaderAddr, (PVOID)g_Loader, LSIZ, nullptr);
    g_NtWriteVirtualMemory(hProcess, ctxAddr, &ctx, sizeof(ctx), nullptr);
    g_NtWriteVirtualMemory(hProcess, tramAddr, tramp, sizeof(tramp), nullptr);

    *pTrampoline = tramAddr;
    return true;
}

// Phase D — find IoCompletion port owned by target (IDA @ 0x140005840)
static HANDLE HijackIoCompletionPort(HANDLE hProcess, DWORD pid) {
    ULONG  bufSz = 0x400000, needed = 0;
    PVOID  pBuf = malloc(bufSz);
    while (g_NtQuerySystemInformation(SystemHandleInformation, pBuf, bufSz, &needed)
        == STATUS_INFO_LENGTH_MISMATCH)
    {
        free(pBuf); bufSz = needed + 0x100000; pBuf = malloc(bufSz);
    }

    auto* hi = (SYSTEM_HANDLE_INFORMATION*)pBuf;
    HANDLE ret = nullptr;
    ULONG64 typeBuf[64] = {};

    for (ULONG i = 0; i < hi->NumberOfHandles && !ret; i++) {
        if (hi->Handles[i].UniqueProcessId != pid) continue;
        HANDLE hLocal = nullptr;
        if (!NT_SUCCESS(g_NtDuplicateObject(hProcess,
            (HANDLE)(ULONG_PTR)hi->Handles[i].HandleValue,
            GetCurrentProcess(), &hLocal, 0, 0, 2))) continue;

        memset(typeBuf, 0, sizeof(typeBuf));
        if (NT_SUCCESS(g_NtQueryObject(hLocal, 2, typeBuf, sizeof(typeBuf), nullptr))) {
            USHORT  len = (USHORT)(typeBuf[0] & 0xFFFF);
            LPCWSTR buf = (LPCWSTR)typeBuf[1];
            if (len >= 0x18 && buf && wcsncmp(buf, L"IoCompletion", 12) == 0)
            {
                ret = hLocal; continue;
            }
        }
        CloseHandle(hLocal);
    }
    free(pBuf);
    if (!ret) std::cout << "failed to find IoCompletion port in target!" << std::endl;
    return ret;
}

// Phase E — CFG whitelist for the 22-byte trampoline (IDA @ 0x140005A03)
static bool BypassCFG(HANDLE hProcess, PVOID tramAddr) {
    if (!g_SetProcessValidCallTargets) return false;
    CFG_CALL_TARGET_INFO ci = { 0, CFG_CALL_TARGET_VALID };
    BOOL ok = g_SetProcessValidCallTargets(hProcess, tramAddr, 22, 1, &ci);
    std::cout << (ok ? "CFG bypassed for Trampoline!" : "failed to whitelist Trampoline in CFG!")
        << std::endl;
    return ok != FALSE;
}

// Phase F — write TP_DIRECT + NtSetIoCompletion (IDA @ 0x140005A83)
static bool TriggerExecution(HANDLE hProcess, HANDLE hPort, PVOID tramAddr) {
    MEMORY_BASIC_INFORMATION mbi = {};
    PVOID cave = nullptr;
    for (PBYTE p = nullptr; VirtualQueryEx(hProcess, p, &mbi, sizeof(mbi));
        p = (PBYTE)mbi.BaseAddress + mbi.RegionSize) {
        if (mbi.State != MEM_COMMIT || mbi.Protect != PAGE_READWRITE || mbi.RegionSize < 0x48)
            continue;
        PBYTE buf = (PBYTE)malloc(mbi.RegionSize);
        SIZE_T rd = 0;
        if (ReadProcessMemory(hProcess, mbi.BaseAddress, buf, mbi.RegionSize, &rd)) {
            for (SIZE_T off = 0; off + 0x48 <= rd; off++) {
                SIZE_T z = 0;
                while (z < 0x48 && !buf[off + z]) z++;
                if (z >= 0x48) { cave = (PBYTE)mbi.BaseAddress + off; break; }
            }
        }
        free(buf);
        if (cave) break;
    }
    if (!cave) { std::cout << "failed to find RW Code Cave for TP_DIRECT!" << std::endl; return false; }

    TP_DIRECT_INJECT tpd = {};
    tpd.Callback = tramAddr;
    g_NtWriteVirtualMemory(hProcess, cave, &tpd, sizeof(tpd), nullptr);

    NTSTATUS st = g_NtSetIoCompletion(hPort, cave, nullptr, 0, 0);
    if (NT_SUCCESS(st)) { std::cout << "sent PoolParty Packet!" << std::endl; return true; }
    return false;
}

// sub_140004D50 — master injection routine
static bool PoolParty_Inject(HANDLE hProcess) {
    SIZE_T rawSz = 0;
    PBYTE  raw = LoadPayloadFromDisk(rawSz);
    if (!raw) { std::cout << "failed to load scorching-exploit.dll" << std::endl; return false; }

    auto* pNt = (PIMAGE_NT_HEADERS64)(raw + ((PIMAGE_DOS_HEADER)raw)->e_lfanew);

    ULONG64 base = MapAndStompPayload(hProcess, raw, rawSz, pNt);
    if (!base) { free(raw); return false; }

    PVOID tram = nullptr;
    if (!BuildLoaderSection(hProcess, base, pNt, &tram))
    {
        free(raw); std::cout << "failed to build loader section!" << std::endl; return false;
    }
    free(raw);

    BypassCFG(hProcess, tram);

    HANDLE hPort = HijackIoCompletionPort(hProcess, GetProcessId(hProcess));
    if (!hPort) return false;

    bool ok = TriggerExecution(hProcess, hPort, tram);
    CloseHandle(hPort);
    return ok;
}

// sub_140009DD0 — main
int main() {
    SeedPRNG();
    ResolveAPIs();

    std::cout << "looking for RobloxPlayerBeta.exe..." << std::endl;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
    HANDLE hProcess = nullptr;

    if (Process32First(hSnap, &pe)) {
        do {
            if (strcmp(pe.szExeFile, "RobloxPlayerBeta.exe") == 0) {
                hProcess = OpenProcess(0x1FFFFFu, FALSE, pe.th32ProcessID);
                break;
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);

    if (!hProcess) {
        std::cout << "Roblox not Found." << std::endl;
        return 1;
    }
    std::cout << "Roblox Found" << std::endl;

    if (PoolParty_Inject(hProcess)) {
        std::cout << "Injected!" << std::endl;
    }

    CloseHandle(hProcess);
    system("pause");
    return 0;
}
