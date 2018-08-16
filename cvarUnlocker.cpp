// To make importing things work
#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <iostream>
#include <windowsx.h>
#include <commctrl.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <string>

// Address of the method to patch
// Debug build of OpenJK
/*
.text : 00D67E54 cmp dword ptr[edx + 24h], 0
.text : 00D67E58 jnz short loc_D67E73
*/
#define ADDR ((void *)0x00D67E58)

// JNZ rel 8
unsigned char EXPECTED_MEM[] = "\x75";

// JMP rel 8
unsigned char PATCHED[] = "\xEB";

main(int argc, char const *argv[])
{

    PROCESSENTRY32 entry;
    DWORD PID = -1;
    BOOL found = FALSE;

    // Do Windows things
    entry.dwSize = sizeof(PROCESSENTRY32);
    // Get all processes
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot == INVALID_HANDLE_VALUE)
    {
        std::cerr << "Can't get list of running processes" << std::endl;
        exit(1);
    }

    // Search for the process using the exe file name
    if (Process32First(snapshot, &entry))
    {
        do
        {
            if (strcmp((char *)entry.szExeFile, "openjk.x86.exe") == 0)
            {
                found = TRUE;
                PID = entry.th32ProcessID;
                std::cout << "Got process: " << PID << " " << entry.szExeFile << std::endl;
                break;
            }
        } while (Process32Next(snapshot, &entry));
    }
    else
    {
        std::cerr << "Can't process list of running processes" << std::endl;
        exit(2);
    }

    if (!found)
    {
        std::cerr << "Can't find process" << std::endl;
        exit(3);
    }

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, PID);

    if (!hProc)
    {
        std::cerr << "Cannot open process." << std::endl;
        exit(4);
    }
    else
    {
        // Make the process halt
        BOOL res_dbg = DebugActiveProcess(PID);
        if (!res_dbg)
        {
            std::cerr << "Can't debug" << std::endl;
            CloseHandle(hProc);
            exit(5);
        }
        DebugSetProcessKillOnExit(FALSE);

        // try reading first to check for expected values
        unsigned char read_mem[sizeof(EXPECTED_MEM) / sizeof(unsigned char) - 1];
        // read from the address that's about to be patched
        BOOL res_read = ReadProcessMemory(hProc, ADDR, &read_mem, sizeof(read_mem), NULL);
        if (res_read)
        {
            std::cout << "Got memory:" << std::endl;
            for (int i = 0; i < sizeof(read_mem); i++)
            {
                std::cout << "\t" << std::hex << (int)read_mem[i] << " ";
            }
            std::cout << std::endl;
        }
        else
        {
            std::cerr << "Memory couldn't be read from process: " << GetLastError() << std::endl;
            exit(88);
        }

        // Check if it has the expected value
        if (memcmp(EXPECTED_MEM, read_mem, sizeof(read_mem)) != 0)
        {
            std::cerr << "Invalid bytes read" << std::endl;
            exit(99);
        }
        else
        {
            std::cout << "Memory verified" << std::endl;
        }

        // Patch the memory
        BOOL res_write = WriteProcessMemory(hProc, ADDR, &PATCHED, sizeof(PATCHED) - 1, NULL);

        if (res_write)
        {
            std::clog << "Memory written to process." << std::endl;
        }
        else
        {
            std::cerr << "Memory couldn't be written to process: " << GetLastError() << std::endl;
        }

        // Stop debugging
        DebugActiveProcessStop(PID);
        CloseHandle(hProc);
    }

    return 0;
}
