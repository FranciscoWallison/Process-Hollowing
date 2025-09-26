#include "stdafx.h"
#include "windows.h"
#include "internals.h"
#include "pe.h"

HMODULE hNTDLL = nullptr;
_NtQueryInformationProcess ntQueryInformationProcess = nullptr;

bool InitializeNtQueryInformationProcess()
{
    hNTDLL = LoadLibraryA("ntdll");
    if (!hNTDLL)
        return false;

    FARPROC fpNtQueryInformationProcess = GetProcAddress(hNTDLL, "NtQueryInformationProcess");
    if (!fpNtQueryInformationProcess)
        return false;

    ntQueryInformationProcess = (_NtQueryInformationProcess)fpNtQueryInformationProcess;
    return true;
}

uintptr_t FindRemotePEB(HANDLE hProcess)
{
    if(!ntQueryInformationProcess)
    {
        if(!InitializeNtQueryInformationProcess())
            return 0;
    }

    PROCESS_BASIC_INFORMATION basicInfo = {0};
    DWORD dwReturnLength = 0;

    ntQueryInformationProcess(hProcess, 0, &basicInfo, sizeof(basicInfo), &dwReturnLength);
    return reinterpret_cast<uintptr_t>(basicInfo.PebBaseAddress);
}

PEB* ReadRemotePEB(HANDLE hProcess)
{
    uintptr_t dwPEBAddress = FindRemotePEB(hProcess);
    if(!dwPEBAddress)
        return nullptr;

    PEB* pPEB = new PEB();

    if(!ReadProcessMemory(hProcess, (LPCVOID)dwPEBAddress, pPEB, sizeof(PEB), nullptr))
    {
        delete pPEB;
        return nullptr;
    }

    return pPEB;
}

PLOADED_IMAGE_EX ReadRemoteImage(HANDLE hProcess, LPCVOID lpImageBaseAddress)
{
    BYTE* lpBuffer = new BYTE[BUFFER_SIZE];
    if(!ReadProcessMemory(hProcess, lpImageBaseAddress, lpBuffer, BUFFER_SIZE, nullptr))
    {
        delete[] lpBuffer;
        return nullptr;	
    }

    auto pDOSHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(lpBuffer);
    auto e_lfanew = pDOSHeader->e_lfanew;
    auto pImage = new LOADED_IMAGE_EX();

    pImage->RawData.assign(lpBuffer, lpBuffer + BUFFER_SIZE);
    delete[] lpBuffer;

    auto basePtr = reinterpret_cast<uintptr_t>(pImage->RawData.data());
    pImage->FileHeader = reinterpret_cast<PIMAGE_NT_HEADERS_T>(basePtr + e_lfanew);
    pImage->NumberOfSections = pImage->FileHeader->FileHeader.NumberOfSections;
    pImage->Sections = reinterpret_cast<PIMAGE_SECTION_HEADER>(basePtr + e_lfanew + sizeof(IMAGE_NT_HEADERS_T));

    return pImage;
}
