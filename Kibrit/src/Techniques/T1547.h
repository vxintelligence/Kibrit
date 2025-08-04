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
#include <string>
#include <vector>
#include <Windows.h>
#include <iostream>
#include <shlobj.h>

namespace CyberSim {

    // Educational demonstration of T1547.001 concepts (safe implementation)
    class TechniqueT1547_001 {
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

        // Registry keys used for persistence demonstration
        std::string m_regKeyPath = "Software\\CyberSim\\Demo";
        std::string m_regValueName = "PersistenceDemo";
        std::string m_startupFolder;
        std::string m_demoFileName = "CyberSimDemo.txt";
        bool m_regKeyCreated = false;
        bool m_startupFileCreated = false;

    public:
        TechniqueT1547_001() {
            m_info.id = "T1547.001";
            m_info.name = "Registry Run Keys / Startup Folder (Educational Demo)";
            m_info.tactic = "Persistence";
            m_info.description = "Educational demonstration of persistence mechanisms using registry run keys and startup folders.";
            m_info.platforms = { "Windows" };
            m_info.dataSource = "Registry monitoring, File monitoring";

            // Get the startup folder path
            char startupPath[MAX_PATH];
            if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startupPath))) {
                m_startupFolder = std::string(startupPath) + "\\";
            }
            else {
                m_startupFolder = "C:\\Windows\\Temp\\";  // Fallback
            }
        }

        TechniqueInfo GetInfo() const {
            return m_info;
        }

        bool Initialize() {
            m_logs.push_back("Initialized T1547.001 Educational Demo");
            m_logs.push_back("This is a safe demonstration of persistence techniques");
            m_logs.push_back("In real scenarios, this would enable malware persistence");
            m_progress = 0.0f;
            m_info.isActive = true;
            m_executed = false;
            return true;
        }

        void Execute() {
            if (!m_info.isActive || m_executed) return;

            int result = 0; // Default to failure state

            m_logs.push_back("Starting educational demonstration...");
            m_progress = 0.1f;

            // Step 1: Demonstrate registry run key persistence
            m_logs.push_back("Step 1: Registry Run Key Persistence Demonstration");

            // Create a demonstration registry key (in HKCU for safety)
            HKEY hKey;
            LONG regResult = RegCreateKeyExA(
                HKEY_CURRENT_USER,
                m_regKeyPath.c_str(),
                0,
                NULL,
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                NULL,
                &hKey,
                NULL
            );

            m_progress = 0.2f;

            if (regResult == ERROR_SUCCESS) {
                m_logs.push_back("Successfully created registry key: HKCU\\" + m_regKeyPath);

                // Create a demonstration value (simulate malware persistence)
                std::string demoValue = "C:\\Windows\\System32\\notepad.exe";
                regResult = RegSetValueExA(
                    hKey,
                    m_regValueName.c_str(),
                    0,
                    REG_SZ,
                    (const BYTE*)demoValue.c_str(),
                    (DWORD)demoValue.length() + 1
                );

                if (regResult == ERROR_SUCCESS) {
                    m_logs.push_back("Successfully created registry value: " + m_regValueName);
                    m_logs.push_back("Set to launch: " + demoValue);
                    m_logs.push_back("This registry value would cause the program to run at startup");
                    m_regKeyCreated = true;
                }
                else {
                    m_logs.push_back("Failed to create registry value: " + std::to_string(regResult));
                }

                RegCloseKey(hKey);
            }
            else {
                m_logs.push_back("Failed to create registry key: " + std::to_string(regResult));
            }

            m_progress = 0.4f;

            // Show educational information about common run keys
            m_logs.push_back("");
            m_logs.push_back("Common Registry Run Keys Used by Attackers:");
            m_logs.push_back("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
            m_logs.push_back("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
            m_logs.push_back("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
            m_logs.push_back("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
            m_logs.push_back("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices");

            m_progress = 0.5f;

            // Step 2: Demonstrate startup folder persistence
            m_logs.push_back("");
            m_logs.push_back("Step 2: Startup Folder Persistence Demonstration");
            m_logs.push_back("Startup folder location: " + m_startupFolder);

            // Create a demo file in the startup folder (just a text file for safety)
            std::string filePath = m_startupFolder + m_demoFileName;
            FILE* file = NULL;
            fopen_s(&file, filePath.c_str(), "w");

            m_progress = 0.7f;

            if (file != NULL) {
                // Write educational content to the file
                fprintf(file, "CyberSim Educational Demo - T1547.001\r\n");
                fprintf(file, "This is a demonstration file showing how attackers use startup folders for persistence.\r\n");
                fprintf(file, "In a real attack, this would be an executable or shortcut that runs at startup.\r\n");
                fprintf(file, "Time created: %s\r\n", GetTimeString().c_str());
                fclose(file);

                m_logs.push_back("Successfully created demo file: " + filePath);
                m_logs.push_back("In a real attack, this would be a malicious executable or shortcut");
                m_startupFileCreated = true;
                result = IDOK;
            }
            else {
                m_logs.push_back("Failed to create demo file: " + std::to_string(GetLastError()));
            }

            m_progress = 0.9f;

            // Log results
            if (result == IDOK) {
                m_logs.push_back("");
                m_logs.push_back("SUCCESS: Educational demo executed successfully");
                m_logs.push_back("Demonstrated two common persistence mechanisms:");
                m_logs.push_back("1. Registry Run Keys");
                m_logs.push_back("2. Startup Folder");
                m_logs.push_back("These techniques are commonly used by malware to survive system restarts");
            }
            else {
                m_logs.push_back("Demo completed with warnings or failures");
                m_logs.push_back("Last error code: " + std::to_string(GetLastError()));
            }

            m_progress = 1.0f;
            m_executed = true;

            m_logs.push_back("");
            m_logs.push_back("Educational demonstration complete");
            m_logs.push_back("Key learning: T1547.001 enables persistence across system restarts");
            m_logs.push_back("Detection: Monitor registry run keys and startup folder changes");
        }

        void Stop() {
            m_info.isActive = false;

            // Clean up created registry keys and files
            if (m_regKeyCreated) {
                HKEY hKey;
                if (RegOpenKeyExA(HKEY_CURRENT_USER, m_regKeyPath.c_str(), 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
                    RegDeleteValueA(hKey, m_regValueName.c_str());
                    RegCloseKey(hKey);
                }
                RegDeleteKeyA(HKEY_CURRENT_USER, m_regKeyPath.c_str());
                m_logs.push_back("Cleaned up demo registry key");
            }

            if (m_startupFileCreated) {
                std::string filePath = m_startupFolder + m_demoFileName;
                DeleteFileA(filePath.c_str());
                m_logs.push_back("Cleaned up demo startup file");
            }

            m_logs.push_back("Technique stopped");
        }

        float GetProgress() const {
            return m_progress;
        }

        std::vector<std::string> GetLogs() const {
            return m_logs;
        }

        void Reset() {
            // Clean up any artifacts before resetting
            Stop();

            m_progress = 0.0f;
            m_executed = false;
            m_logs.clear();
            m_regKeyCreated = false;
            m_startupFileCreated = false;
            m_logs.push_back("Technique reset - ready for next demonstration");
        }

        // Helper function to get current time as string
        std::string GetTimeString() {
            char buffer[80];
            time_t now = time(0);
            struct tm timeinfo;
            localtime_s(&timeinfo, &now);
            strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &timeinfo);
            return std::string(buffer);
        }

        // Educational information methods
        std::vector<std::string> GetSubTechniques() const {
            return {
                "Registry Run Keys",
                "Registry RunOnce Keys",
                "Startup Folder",
                "User Profile Startup Folder",
                "Active Setup",
                "AppInit DLLs",
                "Winlogon Helper DLL"
            };
        }

        std::vector<std::string> GetMitigations() const {
            return {
                "Restrict Registry Permissions - Limit write access to Run keys",
                "Execution Prevention - Use AppLocker or similar to restrict executed files",
                "User Account Control - Use UAC to prevent unauthorized modifications",
                "Startup Program Monitoring - Track changes to startup programs",
                "Privileged Account Management - Restrict admin access",
                "Regular System Auditing - Check for unauthorized startup entries"
            };
        }

        std::vector<std::string> GetDetectionMethods() const {
            return {
                "Monitor registry for additions to Run and RunOnce keys",
                "Track creation of new files in startup folders",
                "Compare current startup items against known-good baseline",
                "Use autoruns.exe to audit startup programs",
                "Monitor processes that are launched at system startup",
                "Use EDR solutions to detect unauthorized persistence mechanisms",
                "Track registry modifications by suspicious processes"
            };
        }

        // Integration with Walnut GUI
        void RenderCustomUI() {
            // This can be implemented to add custom UI elements in the Walnut framework
        }
    };

} // namespace CyberSim