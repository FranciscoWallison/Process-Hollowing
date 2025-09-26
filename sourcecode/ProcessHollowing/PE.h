#pragma once

#include <vector>
#include <map>
#include <cstdint>
#include <Ntsecapi.h>
#include <DbgHelp.h>
#include <intrin.h>

#define BUFFER_SIZE 0x2000

typedef struct _RTL_DRIVE_LETTER_CURDIR {
        USHORT                  Flags;
        USHORT                  Length;
        ULONG                   TimeStamp;
        UNICODE_STRING          DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _LDR_MODULE {
        LIST_ENTRY              InLoadOrderModuleList;
        LIST_ENTRY              InMemoryOrderModuleList;
        LIST_ENTRY              InInitializationOrderModuleList;
        PVOID                   BaseAddress;
        PVOID                   EntryPoint;
        ULONG                   SizeOfImage;
        UNICODE_STRING          FullDllName;
        UNICODE_STRING          BaseDllName;
        ULONG                   Flags;
        SHORT                   LoadCount;
        SHORT                   TlsIndex;
        LIST_ENTRY              HashTableEntry;
        ULONG                   TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;

typedef struct _PEB_LDR_DATA {
        ULONG                   Length;
        BOOLEAN                 Initialized;
        PVOID                   SsHandle;
        LIST_ENTRY              InLoadOrderModuleList;
        LIST_ENTRY              InMemoryOrderModuleList;
        LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
        ULONG                   MaximumLength;
        ULONG                   Length;
        ULONG                   Flags;
        ULONG                   DebugFlags;
        PVOID                   ConsoleHandle;
        ULONG                   ConsoleFlags;
        HANDLE                  StdInputHandle;
        HANDLE                  StdOutputHandle;
        HANDLE                  StdErrorHandle;
        UNICODE_STRING          CurrentDirectoryPath;
        HANDLE                  CurrentDirectoryHandle;
        UNICODE_STRING          DllPath;
        UNICODE_STRING          ImagePathName;
        UNICODE_STRING          CommandLine;
        PVOID                   Environment;
        ULONG                   StartingPositionLeft;
        ULONG                   StartingPositionTop;
        ULONG                   Width;
        ULONG                   Height;
        ULONG                   CharWidth;
        ULONG                   CharHeight;
        ULONG                   ConsoleTextAttributes;
        ULONG                   WindowFlags;
        ULONG                   ShowWindowFlags;
        UNICODE_STRING          WindowTitle;
        UNICODE_STRING          DesktopName;
        UNICODE_STRING          ShellInfo;
        UNICODE_STRING          RuntimeData;
        RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_FREE_BLOCK {
        _PEB_FREE_BLOCK          *Next;
        ULONG                   Size;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;

typedef void (*PPEBLOCKROUTINE)(
                                                                PVOID PebLock
                                                                );

typedef struct _PEB {
        BOOLEAN                 InheritedAddressSpace;
        BOOLEAN                 ReadImageFileExecOptions;
        BOOLEAN                 BeingDebugged;
        BOOLEAN                 Spare;
        HANDLE                  Mutant;
        PVOID                   ImageBaseAddress;
        PPEB_LDR_DATA           LoaderData;
        PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
        PVOID                   SubSystemData;
        PVOID                   ProcessHeap;
        PVOID                   FastPebLock;
        PPEBLOCKROUTINE         FastPebLockRoutine;
        PPEBLOCKROUTINE         FastPebUnlockRoutine;
        ULONG                   EnvironmentUpdateCount;
        PVOID*                  KernelCallbackTable;
        PVOID                   EventLogSection;
        PVOID                   EventLog;
        PPEB_FREE_BLOCK         FreeList;
        ULONG                   TlsExpansionCounter;
        PVOID                   TlsBitmap;
        ULONG                   TlsBitmapBits[0x2];
        PVOID                   ReadOnlySharedMemoryBase;
        PVOID                   ReadOnlySharedMemoryHeap;
        PVOID*                  ReadOnlyStaticServerData;
        PVOID                   AnsiCodePageData;
        PVOID                   OemCodePageData;
        PVOID                   UnicodeCaseTableData;
        ULONG                   NumberOfProcessors;
        ULONG                   NtGlobalFlag;
        BYTE                    Spare2[0x4];
        LARGE_INTEGER           CriticalSectionTimeout;
        ULONG                   HeapSegmentReserve;
        ULONG                   HeapSegmentCommit;
        ULONG                   HeapDeCommitTotalFreeThreshold;
        ULONG                   HeapDeCommitFreeBlockThreshold;
        ULONG                   NumberOfHeaps;
        ULONG                   MaximumNumberOfHeaps;
        PVOID*                  *ProcessHeaps;
        PVOID                   GdiSharedHandleTable;
        PVOID                   ProcessStarterHelper;
        PVOID                   GdiDCAttributeList;
        PVOID                   LoaderLock;
        ULONG                   OSMajorVersion;
        ULONG                   OSMinorVersion;
        ULONG                   OSBuildNumber;
        ULONG                   OSPlatformId;
        ULONG                   ImageSubSystem;
        ULONG                   ImageSubSystemMajorVersion;
        ULONG                   ImageSubSystemMinorVersion;
        ULONG                   GdiHandleBuffer[0x22];
        ULONG                   PostProcessInitRoutine;
        ULONG                   TlsExpansionBitmap;
        BYTE                    TlsExpansionBitmapBits[0x80];
        ULONG                   SessionId;
} PEB, *PPEB;

typedef struct BASE_RELOCATION_BLOCK {
        DWORD PageAddress;
        DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
        USHORT Offset : 12;
        USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

#define CountRelocationEntries(dwBlockSize)                             \
        ((dwBlockSize - sizeof(BASE_RELOCATION_BLOCK)) /                \
        sizeof(BASE_RELOCATION_ENTRY))

#ifdef _WIN64
using IMAGE_NT_HEADERS_T = IMAGE_NT_HEADERS64;
using PIMAGE_NT_HEADERS_T = PIMAGE_NT_HEADERS64;
using IMAGE_THUNK_DATA_T = IMAGE_THUNK_DATA64;
using PIMAGE_THUNK_DATA_T = PIMAGE_THUNK_DATA64;
#else
using IMAGE_NT_HEADERS_T = IMAGE_NT_HEADERS32;
using PIMAGE_NT_HEADERS_T = PIMAGE_NT_HEADERS32;
using IMAGE_THUNK_DATA_T = IMAGE_THUNK_DATA32;
using PIMAGE_THUNK_DATA_T = PIMAGE_THUNK_DATA32;
#endif

struct LOADED_IMAGE_EX {
        std::vector<BYTE> RawData;
        PIMAGE_NT_HEADERS_T FileHeader;
        WORD NumberOfSections;
        PIMAGE_SECTION_HEADER Sections;
};

using PLOADED_IMAGE_EX = LOADED_IMAGE_EX*;

inline PEB* GetPEB()
{
#ifdef _WIN64
        return reinterpret_cast<PEB*>(__readgsqword(0x60));
#else
        return reinterpret_cast<PEB*>(__readfsdword(0x30));
#endif
}

inline PIMAGE_NT_HEADERS_T GetNTHeaders(uintptr_t dwImageBase)
{
        return reinterpret_cast<PIMAGE_NT_HEADERS_T>(dwImageBase +
                reinterpret_cast<PIMAGE_DOS_HEADER>(dwImageBase)->e_lfanew);
}

inline PLOADED_IMAGE_EX GetLoadedImage(uintptr_t dwImageBase)
{
        auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(dwImageBase);

        auto pImage = new LOADED_IMAGE_EX();
        pImage->FileHeader = reinterpret_cast<PIMAGE_NT_HEADERS_T>(dwImageBase + pDosHeader->e_lfanew);
        pImage->NumberOfSections = pImage->FileHeader->FileHeader.NumberOfSections;
        pImage->Sections = reinterpret_cast<PIMAGE_SECTION_HEADER>(dwImageBase + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS_T));

        return pImage;
}

inline char* GetDLLName(uintptr_t dwImageBase,
                                                IMAGE_IMPORT_DESCRIPTOR ImageImportDescriptor)
{
        return reinterpret_cast<char*>(dwImageBase + ImageImportDescriptor.Name);
}

inline IMAGE_DATA_DIRECTORY GetImportDirectory(PIMAGE_NT_HEADERS_T pFileHeader)
{
        return pFileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
}

inline PIMAGE_IMPORT_DESCRIPTOR GetImportDescriptors(PIMAGE_NT_HEADERS_T pFileHeader,
                                                                                                         IMAGE_DATA_DIRECTORY ImportDirectory)
{
        return reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pFileHeader->OptionalHeader.ImageBase +
                ImportDirectory.VirtualAddress);
}

inline PIMAGE_THUNK_DATA_T GetILT(uintptr_t dwImageBase,
                                                                  IMAGE_IMPORT_DESCRIPTOR ImageImportDescriptor)
{
        return reinterpret_cast<PIMAGE_THUNK_DATA_T>(dwImageBase + ImageImportDescriptor.OriginalFirstThunk);
}

inline PIMAGE_THUNK_DATA_T GetIAT(uintptr_t dwImageBase,
                                                                  IMAGE_IMPORT_DESCRIPTOR ImageImportDescriptor)
{
        return reinterpret_cast<PIMAGE_THUNK_DATA_T>(dwImageBase + ImageImportDescriptor.FirstThunk);
}

inline PIMAGE_IMPORT_BY_NAME GetImportByName(uintptr_t dwImageBase,
                                                                                         IMAGE_THUNK_DATA_T itdImportLookup)
{
        return reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(dwImageBase + static_cast<uintptr_t>(itdImportLookup.u1.AddressOfData));
}

extern std::map<PWSTR, std::vector<DWORD>> gCodeChecksums;

void WalkLoadOrderModules(void (*pLdrModuleFunction)(PLDR_MODULE, DWORD, PVOID), PVOID pParameters);

void GenerateCodeChecksums(PLDR_MODULE pLdrModule, std::vector<DWORD>* pChecksums);

void SetInitialLdrCodeChecksums(PLDR_MODULE pLdrModule, DWORD dwIndex, PVOID pParams);

void ValidateLdrCodeChecksums(PLDR_MODULE pLdrModule, DWORD dwIndex, PVOID pParams);

typedef struct _IAT_BACKUP_INFO {
        DWORD BackupLength;
        DWORD*** IATBackup;
} IAT_BACKUP_INFO, *PIAT_BACKUP_INFO;

DWORD** BackupIAT(uintptr_t dwImageBase);

void RepairIAT(uintptr_t dwImageBase, DWORD** pIATBackup);

uintptr_t FindRemotePEB(HANDLE hProcess);

PEB* ReadRemotePEB(HANDLE hProcess);

PLOADED_IMAGE_EX ReadRemoteImage(HANDLE hProcess, LPCVOID lpImageBaseAddress);
