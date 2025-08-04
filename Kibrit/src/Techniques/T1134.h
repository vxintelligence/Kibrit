#pragma once
#include <string>
#include <vector>
#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <psapi.h>
#include <sddl.h>

namespace CyberSim {

    // Educational demonstration of T1134 concepts (safe implementation)
    class TechniqueT1134 {
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

    public:
        TechniqueT1134() {
            m_info.id = "T1134";
            m_info.name = "Access Token Manipulation (Educational Demo)";
            m_info.tactic = "Defense Evasion, Privilege Escalation";
            m_info.description = "Educational demonstration of token manipulation for privilege escalation and defense evasion.";
            m_info.platforms = { "Windows" };
            m_info.dataSource = "Process monitoring, API calls";
        }

        TechniqueInfo GetInfo() const {
            return m_info;
        }

        bool Initialize() {
            m_logs.push_back("Initialized T1134 Educational Demo");
            m_logs.push_back("This is a safe demonstration that shows token manipulation");
            m_logs.push_back("In real scenarios, this would enable privilege escalation");
            m_progress = 0.0f;
            m_info.isActive = true;
            m_executed = false;
            return true;
        }

        void Execute() {
            if (!m_info.isActive || m_executed) return;

            int result = 0; // Default to failure state

            m_logs.push_back("Starting educational demonstration...");
            m_progress = 0.2f;

            m_logs.push_back("Step 1: Retrieve current process token");
            m_progress = 0.3f;

            // Get the current process token
            HANDLE currentToken = NULL;
            BOOL success = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_PRIVILEGES, &currentToken);
            if (!success || currentToken == NULL) {
                m_logs.push_back("Failed to open process token: " + std::to_string(GetLastError()));
                m_logs.push_back("Demo failed");
                m_progress = 1.0f;
                m_executed = true;
                return;
            }
            m_logs.push_back("Successfully retrieved current process token");
            m_progress = 0.4f;

            // Step 2: Display token information (for educational purposes)
            m_logs.push_back("Step 2: Analyzing token information");

            // Get token user information
            DWORD userInfoSize = 0;
            GetTokenInformation(currentToken, TokenUser, NULL, 0, &userInfoSize);
            if (userInfoSize > 0) {
                PTOKEN_USER tokenUser = (PTOKEN_USER)malloc(userInfoSize);
                if (tokenUser != NULL) {
                    if (GetTokenInformation(currentToken, TokenUser, tokenUser, userInfoSize, &userInfoSize)) {
                        // Convert SID to string for display
                        LPSTR sidString = NULL;
                        if (ConvertSidToStringSidA(tokenUser->User.Sid, &sidString)) {
                            m_logs.push_back("Token User SID: " + std::string(sidString));
                            LocalFree(sidString);
                        }

                        // Get the user name from SID
                        char userName[256] = { 0 };
                        char domainName[256] = { 0 };
                        DWORD nameLen = 256;
                        DWORD domainLen = 256;
                        SID_NAME_USE sidType;
                        if (LookupAccountSidA(NULL, tokenUser->User.Sid, userName, &nameLen, domainName, &domainLen, &sidType)) {
                            m_logs.push_back("Token User: " + std::string(domainName) + "\\" + std::string(userName));
                        }
                    }
                    free(tokenUser);
                }
            }
            m_progress = 0.5f;

            // Get token privileges
            DWORD privSize = 0;
            GetTokenInformation(currentToken, TokenPrivileges, NULL, 0, &privSize);
            if (privSize > 0) {
                PTOKEN_PRIVILEGES tokenPrivileges = (PTOKEN_PRIVILEGES)malloc(privSize);
                if (tokenPrivileges != NULL) {
                    if (GetTokenInformation(currentToken, TokenPrivileges, tokenPrivileges, privSize, &privSize)) {
                        m_logs.push_back("Token has " + std::to_string(tokenPrivileges->PrivilegeCount) + " privileges");

                        // Log a few privileges for educational purposes (limit to first 3)
                        for (DWORD i = 0; i < min(tokenPrivileges->PrivilegeCount, (DWORD)3); i++) {
                            LUID luid = tokenPrivileges->Privileges[i].Luid;
                            DWORD nameLen = 256;
                            char privName[256] = { 0 };
                            if (LookupPrivilegeNameA(NULL, &luid, privName, &nameLen)) {
                                std::string enabledStatus = "";
                                if (tokenPrivileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) {
                                    enabledStatus = " (Enabled)";
                                }
                                else {
                                    enabledStatus = " (Disabled)";
                                }
                                m_logs.push_back("Privilege: " + std::string(privName) + enabledStatus);
                            }
                        }
                    }
                    free(tokenPrivileges);
                }
            }
            m_progress = 0.6f;

            // Step 3: Duplicate the token (educational demonstration)
            m_logs.push_back("Step 3: Demonstrating token duplication");

            HANDLE duplicateToken = NULL;
            if (DuplicateToken(currentToken, SecurityImpersonation, &duplicateToken)) {
                m_logs.push_back("Successfully duplicated token with SecurityImpersonation level");

                // Check token impersonation level (educational)
                SECURITY_IMPERSONATION_LEVEL impersonationLevel;
                DWORD returnLength = 0;
                if (GetTokenInformation(duplicateToken, TokenImpersonationLevel, &impersonationLevel, sizeof(DWORD), &returnLength)) {

                    std::string impLevel;
                    switch (impersonationLevel) {
                    case SecurityAnonymous:
                        impLevel = "Anonymous";
                        break;
                    case SecurityIdentification:
                        impLevel = "Identification";
                        break;
                    case SecurityImpersonation:
                        impLevel = "Impersonation";
                        break;
                    case SecurityDelegation:
                        impLevel = "Delegation";
                        break;
                    default:
                        impLevel = "Unknown";
                    }
                    m_logs.push_back("Duplicate token impersonation level: " + impLevel);
                }

                // Step 4: In a real attack, this would be used to impersonate another user
                m_logs.push_back("Step 4: Token impersonation demonstration");

                // Educational - safely enable privileges (without actually using them)
                TOKEN_PRIVILEGES tp;
                LUID luid;

                if (LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
                    tp.PrivilegeCount = 1;
                    tp.Privileges[0].Luid = luid;
                    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

                    // Just try to adjust the privileges for educational purposes
                    if (AdjustTokenPrivileges(duplicateToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
                        m_logs.push_back("Educational: Adjusted token privileges (SE_DEBUG_NAME)");
                        if (GetLastError() == ERROR_SUCCESS) {
                            m_logs.push_back("Privilege successfully enabled");
                        }
                        else {
                            m_logs.push_back("Privilege adjustment succeeded but privilege not enabled");
                        }
                    }
                    else {
                        m_logs.push_back("Failed to adjust token privileges: " + std::to_string(GetLastError()));
                    }
                }

                // Close the duplicate token
                CloseHandle(duplicateToken);
                result = IDOK; // Mark as successful
            }
            else {
                m_logs.push_back("Failed to duplicate token: " + std::to_string(GetLastError()));
            }
            m_progress = 0.8f;

            // Step 5: Clean up and display results
            if (currentToken) {
                CloseHandle(currentToken);
            }

            m_progress = 0.9f;

            // Log results
            if (result == IDOK) {
                m_logs.push_back("SUCCESS: Educational demo executed successfully");
                m_logs.push_back("Token manipulation demonstrated (safely)");
                m_logs.push_back("In real attacks, this would lead to privilege escalation");
            }
            else {
                m_logs.push_back("Demo completed with warnings or failures");
                m_logs.push_back("Last error code: " + std::to_string(GetLastError()));
            }

            m_progress = 1.0f;
            m_executed = true;

            m_logs.push_back("Educational demonstration complete");
            m_logs.push_back("Key learning: T1134 enables privilege escalation and defense evasion");
            m_logs.push_back("Detection: Monitor for unusual token manipulation operations");
        }

        void Stop() {
            m_info.isActive = false;
            m_logs.push_back("Technique stopped");
        }

        float GetProgress() const {
            return m_progress;
        }

        std::vector<std::string> GetLogs() const {
            return m_logs;
        }

        void Reset() {
            m_progress = 0.0f;
            m_executed = false;
            m_logs.clear();
            m_logs.push_back("Technique reset - ready for next demonstration");
        }

        // Educational information methods
        std::vector<std::string> GetSubTechniques() const {
            return {
                "T1134.001 - Token Impersonation/Theft",
                "T1134.002 - Create Process with Token",
                "T1134.003 - Make and Impersonate Token",
                "T1134.004 - Parent PID Spoofing",
                "T1134.005 - SID-History Injection"
            };
        }

        std::vector<std::string> GetMitigations() const {
            return {
                "Privileged Account Management - Restrict and protect admin accounts",
                "User Account Management - Apply principle of least privilege",
                "Audit - Monitor for suspicious token manipulation activities",
                "Operating System Configuration - Use protected processes",
                "Access Control - Limit access to token creation and manipulation APIs"
            };
        }

        std::vector<std::string> GetDetectionMethods() const {
            return {
                "Monitor token creation and manipulation API calls",
                "Track privilege escalation events",
                "Detect unusual token impersonation patterns",
                "Monitor child processes created with different security contexts",
                "Track process token modifications",
                "Analyze authentication events for unexpected identities",
                "Monitor for suspicious SID changes or additions"
            };
        }

        // Integration with Walnut GUI
        void RenderCustomUI() {
            // This can be implemented to add custom UI elements in the Walnut framework
        }
    };

} // namespace CyberSim