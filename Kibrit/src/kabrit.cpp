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

#define _WINSOCKAPI_ 
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shellapi.h>

#include "uil/Application.h"
#include "uil/EntryPoint.h"
#include "uil/Image.h"
#include <memory>
#include <vector>
#include <map>
#include <string>
#include <chrono>
#include <random>
#include <fstream>
#include <filesystem>
#include <ctime>

extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

#pragma comment(lib, "lua51.lib")

// Include all techniques here for easy access
#include "Techniques/T1055.h" 
#include "Techniques/T1134.h"
#include "Techniques/T1547.h"
#include "Techniques/T1059.h"

using namespace Walnut;

// Forward declarations
class CyberSimLayer;
class ITechnique;

// Base interface for all MITRE ATT&CK techniques
class ITechnique {
public:
    virtual ~ITechnique() = default;
    virtual std::string GetID() const = 0;
    virtual std::string GetName() const = 0;
    virtual std::string GetTactic() const = 0;
    virtual std::string GetDescription() const = 0;
    virtual bool Initialize() = 0;
    virtual void Execute() = 0;
    virtual void Stop() = 0;
    virtual float GetProgress() const = 0;
    virtual std::vector<std::string> GetLogs() const = 0;
    virtual bool IsRunning() const = 0;
    virtual void RenderCustomUI() = 0;
};

class CyberSimLayer : public Walnut::Layer {
public:
    CyberSimLayer();

    void LoadLuaTechnique(const std::string& scriptPath);
    void LoadAllLuaScripts(const std::string& directory = "scripts");
    void ExportData(bool logs, bool statistics, bool configuration);
    void InitializeAllTechniques();
    void StopAllTechniques();
    void ResetAllTechniques();
    void NewSession();
    void AddGlobalLog(const std::string& message);
    void ShowExportDialog() { m_showExportDialog = true; }
    void ShowImportDialog() { m_showImportDialog = true; }
    void ShowSettings() { m_showSettings = true; }
    void ShowAbout() { m_showAbout = true; }
    void ShowTechniqueInfo(int techniqueIndex);
    void ClearLogs();

    // Getters for menu system
    size_t GetTechniqueCount() const { return m_techniques.size(); }
    ITechnique* GetTechnique(int index);

    // UI state getters and setters
    bool& GetShowStatistics() { return m_showStatistics; }
    bool& GetShowLogs() { return m_showLogs; }
    bool& GetShowTechniqueDetails() { return m_showTechniqueDetails; }

    virtual void OnUIRender() override;

private:
    std::vector<std::unique_ptr<ITechnique>> m_techniques;
    int m_selectedTechnique = 0;

    // UI State variables
    bool m_showStatistics = true;
    bool m_showAbout = false;
    bool m_showLogs = true;
    bool m_showTechniqueDetails = true;
    bool m_showSettings = false;
    bool m_showExportDialog = false;
    bool m_showImportDialog = false;
    bool m_showTechniqueInfo = false;
    bool m_autoScroll = true;

    // Session management
    std::string m_sessionName = "Default Session";
    std::vector<std::string> m_globalLogs;
    bool m_sessionModified = false;

    void RenderHeader();
    void RenderTechniquesList();
    void RenderSelectedTechnique();
    void RenderStatisticsWindow();
    void RenderLogsWindow();
    void RenderAboutWindow();
    void RenderSettingsModal();
    void RenderExportModal();
    void RenderTechniqueInfoModal();

    int GetInitializedTechniquesCount() const;
    int GetRunningTechniquesCount() const;
    int GetCompletedTechniquesCount() const;
    float GetOverallProgress() const;
    void UpdateGlobalLogs();
};

class T1134Adapter : public ITechnique {
private:
    CyberSim::TechniqueT1134 m_technique;
    bool m_isRunning = false;

public:
    std::string GetID() const override { return m_technique.GetInfo().id; }
    std::string GetName() const override { return m_technique.GetInfo().name; }
    std::string GetTactic() const override { return m_technique.GetInfo().tactic; }
    std::string GetDescription() const override { return m_technique.GetInfo().description; }
    bool IsRunning() const override { return m_isRunning; }

    bool Initialize() override {
        return m_technique.Initialize();
    }

    void Execute() override {
        m_isRunning = true;
        m_technique.Execute();
        m_isRunning = false;
    }

    void Stop() override {
        m_technique.Stop();
        m_isRunning = false;
    }

    float GetProgress() const override {
        return m_technique.GetProgress();
    }

    std::vector<std::string> GetLogs() const override {
        return m_technique.GetLogs();
    }

    void RenderCustomUI() override {
        if (ImGui::CollapsingHeader("Access Token Manipulation (T1134)")) {
            ImGui::Text("Status: %s", m_isRunning ? "Running" : "Ready");
            ImGui::Text("Progress: %.%%", GetProgress() * 100.0f);

            if (GetProgress() > 0.0f) {
                ImGui::ProgressBar(GetProgress(), ImVec2(-1, 0));
            }

            ImGui::Separator();

            // Control buttons
            if (!m_isRunning) {
                if (ImGui::Button("Execute Demo")) {
                    Execute();
                }
                ImGui::SameLine();
                if (ImGui::Button("Reset")) {
                    m_technique.Reset();
                }
            }
            else {
                if (ImGui::Button("Stop")) {
                    Stop();
                }
            }

            ImGui::Separator();

            if (ImGui::CollapsingHeader("Sub-Techniques")) {
                auto subTechniques = m_technique.GetSubTechniques();
                for (const auto& sub : subTechniques) {
                    ImGui::BulletText("%s", sub.c_str());
                }
            }

            if (ImGui::CollapsingHeader("Mitigations")) {
                auto mitigations = m_technique.GetMitigations();
                for (const auto& mitigation : mitigations) {
                    ImGui::BulletText("%s", mitigation.c_str());
                }
            }

            if (ImGui::CollapsingHeader("Detection Methods")) {
                auto detections = m_technique.GetDetectionMethods();
                for (const auto& detection : detections) {
                    ImGui::BulletText("%s", detection.c_str());
                }
            }

            // Logs
            if (ImGui::CollapsingHeader("Execution Logs")) {
                ImGui::BeginChild("LogsChild", ImVec2(0, 200), true);
                auto logs = GetLogs();
                for (const auto& log : logs) {
                    ImGui::TextWrapped("[LOG] %s", log.c_str());
                }
                if (!logs.empty()) {
                    ImGui::SetScrollHereY(1.0f);
                }
                ImGui::EndChild();
            }
        }
    }
};

class T1059_003Adapter : public ITechnique {
private:
    CyberSim::TechniqueT1059_003 m_technique;
    bool m_isRunning = false;
    char m_ipBuffer[16] = "127.0.0.1";
    int m_port = 4444;

public:
    std::string GetID() const override { return m_technique.GetInfo().id; }
    std::string GetName() const override { return m_technique.GetInfo().name; }
    std::string GetTactic() const override { return m_technique.GetInfo().tactic; }
    std::string GetDescription() const override { return m_technique.GetInfo().description; }
    bool IsRunning() const override { return m_isRunning; }

    bool Initialize() override {
        return m_technique.Initialize();
    }

    void Execute() override {
        // Set the current IP and port from the UI inputs
        m_technique.SetIPAddress(m_ipBuffer);
        m_technique.SetPort(m_port);

        m_isRunning = true;
        m_technique.Execute();
        m_isRunning = false;
    }

    void Stop() override {
        m_technique.Stop();
        m_isRunning = false;
    }

    float GetProgress() const override {
        return m_technique.GetProgress();
    }

    std::vector<std::string> GetLogs() const override {
        return m_technique.GetLogs();
    }

    void RenderCustomUI() override {
        if (ImGui::CollapsingHeader("Windows Command Shell - Reverse Shell (T1059.003)")) {
            ImGui::Text("Status: %s", m_isRunning ? "Running" : "Ready");
            ImGui::Text("Progress: %.1f%%", GetProgress() * 100.0f);

            if (GetProgress() > 0.0f) {
                ImGui::ProgressBar(GetProgress(), ImVec2(-1, 0));
            }

            ImGui::Separator();

            // IP Address and Port inputs
            ImGui::Text("Connection Parameters (Simulation Only)");
            ImGui::InputText("IP Address", m_ipBuffer, IM_ARRAYSIZE(m_ipBuffer));
            ImGui::InputInt("Port", &m_port);

            // Clamp port to valid range
            if (m_port < 1) m_port = 1;
            if (m_port > 65535) m_port = 65535;

            ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.0f, 1.0f),
                "Educational Demo - No actual connection will be made");

            ImGui::Separator();

            // Control buttons
            if (!m_isRunning) {
                if (ImGui::Button("Execute Demo")) {
                    Execute();
                }
                ImGui::SameLine();
                if (ImGui::Button("Reset")) {
                    m_technique.Reset();
                }
            }
            else {
                if (ImGui::Button("Stop")) {
                    Stop();
                }
            }

            ImGui::Separator();

            // Educational information
            if (ImGui::CollapsingHeader("Sub-Techniques")) {
                auto subTechniques = m_technique.GetSubTechniques();
                for (const auto& sub : subTechniques) {
                    ImGui::BulletText("%s", sub.c_str());
                }
            }

            if (ImGui::CollapsingHeader("Mitigations")) {
                auto mitigations = m_technique.GetMitigations();
                for (const auto& mitigation : mitigations) {
                    ImGui::BulletText("%s", mitigation.c_str());
                }
            }

            if (ImGui::CollapsingHeader("Detection Methods")) {
                auto detections = m_technique.GetDetectionMethods();
                for (const auto& detection : detections) {
                    ImGui::BulletText("%s", detection.c_str());
                }
            }

            // Logs
            if (ImGui::CollapsingHeader("Execution Logs")) {
                ImGui::BeginChild("LogsChild", ImVec2(0, 200), true);
                auto logs = GetLogs();
                for (const auto& log : logs) {
                    ImGui::TextWrapped("[LOG] %s", log.c_str());
                }
                if (!logs.empty()) {
                    ImGui::SetScrollHereY(1.0f);
                }
                ImGui::EndChild();
            }
        }
    }
};

class T1547_001Adapter : public ITechnique {
private:
    CyberSim::TechniqueT1547_001 m_technique;
    bool m_isRunning = false;
    bool m_isInitialized = false;

public:
    std::string GetID() const override { return m_technique.GetInfo().id; }
    std::string GetName() const override { return m_technique.GetInfo().name; }
    std::string GetTactic() const override { return m_technique.GetInfo().tactic; }
    std::string GetDescription() const override { return m_technique.GetInfo().description; }
    bool IsRunning() const override { return m_isRunning; }

    bool Initialize() override {
        return m_technique.Initialize();
    }

    void Execute() override {
        m_isRunning = true;
        m_technique.Execute();
        m_isRunning = false;
    }

    void Stop() override {
        m_technique.Stop();
        m_isRunning = false;
    }

    float GetProgress() const override {
        return m_technique.GetProgress();
    }

    std::vector<std::string> GetLogs() const override {
        return m_technique.GetLogs();
    }

    void RenderCustomUI() override {
        if (ImGui::CollapsingHeader("Registry Run Keys / Startup Folder (T1547.001)")) {
            ImGui::Text("Status: %s", m_isRunning ? "Running" : "Ready");
            ImGui::Text("Progress: %.1f%%", GetProgress() * 100.0f);

            if (GetProgress() > 0.0f) {
                ImGui::ProgressBar(GetProgress(), ImVec2(-1, 0));
            }

            ImGui::Separator();

            // Control buttons
            if (!m_isRunning) {
                if (ImGui::Button("Execute Demo")) {
                    Execute();
                }
                ImGui::SameLine();
                if (ImGui::Button("Reset")) {
                    m_technique.Reset();
                }
            }
            else {
                if (ImGui::Button("Stop")) {
                    Stop();
                }
            }

            ImGui::Separator();

            // Educational information
            if (ImGui::CollapsingHeader("Sub-Techniques")) {
                auto subTechniques = m_technique.GetSubTechniques();
                for (const auto& sub : subTechniques) {
                    ImGui::BulletText("%s", sub.c_str());
                }
            }

            if (ImGui::CollapsingHeader("Mitigations")) {
                auto mitigations = m_technique.GetMitigations();
                for (const auto& mitigation : mitigations) {
                    ImGui::BulletText("%s", mitigation.c_str());
                }
            }

            if (ImGui::CollapsingHeader("Detection Methods")) {
                auto detections = m_technique.GetDetectionMethods();
                for (const auto& detection : detections) {
                    ImGui::BulletText("%s", detection.c_str());
                }
            }

            // Logs
            if (ImGui::CollapsingHeader("Execution Logs")) {
                ImGui::BeginChild("LogsChild", ImVec2(0, 200), true);
                auto logs = GetLogs();
                for (const auto& log : logs) {
                    ImGui::TextWrapped("[LOG] %s", log.c_str());
                }
                if (!logs.empty()) {
                    ImGui::SetScrollHereY(1.0f);
                }
                ImGui::EndChild();
            }
        }
    }
};

// Adapter class to make our T1055 work with the interface
class T1055Adapter : public ITechnique {
private:
    CyberSim::TechniqueT1055 m_technique;
    bool m_isRunning = false;

public:
    std::string GetID() const override { return m_technique.GetInfo().id; }
    std::string GetName() const override { return m_technique.GetInfo().name; }
    std::string GetTactic() const override { return m_technique.GetInfo().tactic; }
    std::string GetDescription() const override { return m_technique.GetInfo().description; }
    bool IsRunning() const override { return m_isRunning; }

    bool Initialize() override {
        return m_technique.Initialize();
    }

    void Execute() override {
        m_isRunning = true;
        m_technique.Execute();
        m_isRunning = false;
    }

    void Stop() override {
        m_technique.Stop();
        m_isRunning = false;
    }

    float GetProgress() const override {
        return m_technique.GetProgress();
    }

    std::vector<std::string> GetLogs() const override {
        return m_technique.GetLogs();
    }

    void RenderCustomUI() override {
        if (ImGui::CollapsingHeader("Process Injection (T1055)")) {
            ImGui::Text("Status: %s", m_isRunning ? "Running" : "Ready");
            ImGui::Text("Progress: %.1f%%", GetProgress() * 100.0f);

            if (GetProgress() > 0.0f) {
                ImGui::ProgressBar(GetProgress(), ImVec2(-1, 0));
            }

            ImGui::Separator();

            // Control buttons
            if (!m_isRunning) {
                if (ImGui::Button("Execute Demo")) {
                    Execute();
                }
                ImGui::SameLine();
                if (ImGui::Button("Reset")) {
                    m_technique.Reset();
                }
            }
            else {
                if (ImGui::Button("Stop")) {
                    Stop();
                }
            }

            ImGui::Separator();

            // Educational information
            if (ImGui::CollapsingHeader("Sub-Techniques")) {
                auto subTechniques = m_technique.GetSubTechniques();
                for (const auto& sub : subTechniques) {
                    ImGui::BulletText("%s", sub.c_str());
                }
            }

            if (ImGui::CollapsingHeader("Mitigations")) {
                auto mitigations = m_technique.GetMitigations();
                for (const auto& mitigation : mitigations) {
                    ImGui::BulletText("%s", mitigation.c_str());
                }
            }

            if (ImGui::CollapsingHeader("Detection Methods")) {
                auto detections = m_technique.GetDetectionMethods();
                for (const auto& detection : detections) {
                    ImGui::BulletText("%s", detection.c_str());
                }
            }

            // Logs
            if (ImGui::CollapsingHeader("Execution Logs")) {
                ImGui::BeginChild("LogsChild", ImVec2(0, 200), true);
                auto logs = GetLogs();
                for (const auto& log : logs) {
                    ImGui::TextWrapped("[LOG] %s", log.c_str());
                }
                if (!logs.empty()) {
                    ImGui::SetScrollHereY(1.0f);
                }
                ImGui::EndChild();
            }
        }
    }
};

// Compatibility function for older Lua versions
static int lua_safe_len(lua_State* L, int idx) {
#if LUA_VERSION_NUM >= 502
    return (int)lua_rawlen(L, idx);
#else
    return (int)lua_objlen(L, idx);
#endif
}

class LuaBridge {
public:
    static void RegisterKibritAPI(lua_State* L, CyberSimLayer* cybersim) {
        // Store the CyberSim instance for use in callbacks
        lua_pushlightuserdata(L, cybersim);
        lua_setglobal(L, "__cybersim_instance");

        // Register kibrit table
        lua_newtable(L);

        // kibrit.log function
        lua_pushcfunction(L, kibrit_log);
        lua_setfield(L, -2, "log");

        // kibrit.sleep function
        lua_pushcfunction(L, kibrit_sleep);
        lua_setfield(L, -2, "sleep");

        // kibrit.get_time function
        lua_pushcfunction(L, kibrit_get_time);
        lua_setfield(L, -2, "get_time");

        // Register UI table
        lua_newtable(L);
        lua_pushcfunction(L, ui_text);
        lua_setfield(L, -2, "text");

        lua_pushcfunction(L, ui_button);
        lua_setfield(L, -2, "button");

        lua_pushcfunction(L, ui_progress_bar);
        lua_setfield(L, -2, "progress_bar");

        lua_pushcfunction(L, ui_collapsing_header);
        lua_setfield(L, -2, "collapsing_header");

        lua_setfield(L, -2, "ui");

        // Set kibrit as global
        lua_setglobal(L, "kibrit");
    }

private:
    static CyberSimLayer* GetCyberSimInstance(lua_State* L) {
        lua_getglobal(L, "__cybersim_instance");
        CyberSimLayer* cybersim = static_cast<CyberSimLayer*>(lua_touserdata(L, -1));
        lua_pop(L, 1);
        return cybersim;
    }

    // Kibrit API functions
    static int kibrit_log(lua_State* L) {
        const char* message = luaL_checkstring(L, 1);
        CyberSimLayer* cybersim = GetCyberSimInstance(L);
        if (cybersim) {
            cybersim->AddGlobalLog("[LUA] " + std::string(message));
        }
        return 0;
    }

    static int kibrit_sleep(lua_State* L) {
        int milliseconds = (int)luaL_checkinteger(L, 1);
        Sleep(milliseconds); // Windows sleep
        return 0;
    }

    static int kibrit_get_time(lua_State* L) {
        lua_pushnumber(L, ImGui::GetTime());
        return 1;
    }

    // UI API functions (these would be called during rendering)
    static int ui_text(lua_State* L) {
        const char* text = luaL_checkstring(L, 1);
        ImGui::Text("%s", text);
        return 0;
    }

    static int ui_button(lua_State* L) {
        const char* label = luaL_checkstring(L, 1);
        bool clicked = ImGui::Button(label);
        lua_pushboolean(L, clicked);
        return 1;
    }

    static int ui_progress_bar(lua_State* L) {
        float progress = (float)luaL_checknumber(L, 1);
        ImGui::ProgressBar(progress, ImVec2(-1, 0), "%.1f%%");
        return 0;
    }

    static int ui_collapsing_header(lua_State* L) {
        const char* label = luaL_checkstring(L, 1);
        bool open = ImGui::CollapsingHeader(label);
        lua_pushboolean(L, open);
        return 1;
    }
};

class LuaTechnique : public ITechnique {
private:
    lua_State* L;
    std::string m_scriptPath;
    std::string m_id;
    std::string m_name;
    std::string m_tactic;
    std::string m_description;
    std::string m_author;
    CyberSimLayer* m_cybersim;
    bool m_loaded;
    bool IsLuaTechnique() const { return true; }
    std::string GetAuthor() const { return m_author; }

public:
    LuaTechnique(const std::string& scriptPath, CyberSimLayer* cybersim)
        : m_scriptPath(scriptPath), m_cybersim(cybersim), m_loaded(false) {
        L = luaL_newstate();
        luaL_openlibs(L);
        LuaBridge::RegisterKibritAPI(L, cybersim);
        LoadScript();
    }

    ~LuaTechnique() {
        if (L) {
            lua_close(L);
        }
    }

    bool LoadScript() {
        // Load and execute the Lua script
        if (luaL_dofile(L, m_scriptPath.c_str()) != 0) {
            std::string error = lua_tostring(L, -1);
            m_cybersim->AddGlobalLog("Lua Error loading " + m_scriptPath + ": " + error);
            return false;
        }

        // Get the technique table (script should return a table)
        if (!lua_istable(L, -1)) {
            m_cybersim->AddGlobalLog("Error: Lua script must return a table");
            return false;
        }

        // Store the technique table as global "technique"
        lua_setglobal(L, "technique");

        // Extract info
        ExtractInfo();
        m_loaded = true;
        return true;
    }

private:
    void ExtractInfo() {
        lua_getglobal(L, "technique");
        if (lua_istable(L, -1)) {
            // Get info table
            lua_getfield(L, -1, "info");
            if (lua_istable(L, -1)) {
                lua_getfield(L, -1, "id");
                if (lua_isstring(L, -1)) {
                    m_id = lua_tostring(L, -1);
                }
                lua_pop(L, 1);

                lua_getfield(L, -1, "name");
                if (lua_isstring(L, -1)) {
                    m_name = lua_tostring(L, -1);
                }
                lua_pop(L, 1);

                lua_getfield(L, -1, "tactic");
                if (lua_isstring(L, -1)) {
                    m_tactic = lua_tostring(L, -1);
                }
                lua_pop(L, 1);

                lua_getfield(L, -1, "description");
                if (lua_isstring(L, -1)) {
                    m_description = lua_tostring(L, -1);
                }
                lua_pop(L, 1);

                lua_getfield(L, -1, "author");
                if (lua_isstring(L, -1)) {
                    m_author = lua_tostring(L, -1);
                }
                else {
                    m_author = "vxintelligence";
                }
                lua_pop(L, 1);
            }
            lua_pop(L, 1); // pop info table
        }
        lua_pop(L, 1); // pop technique table
    }

    bool CallLuaFunction(const char* functionName) {
        lua_getglobal(L, "technique");
        if (!lua_istable(L, -1)) {
            lua_pop(L, 1);
            return false;
        }

        lua_getfield(L, -1, functionName);
        if (!lua_isfunction(L, -1)) {
            lua_pop(L, 2);
            return false;
        }

        // Push self (technique table) as first parameter
        lua_pushvalue(L, -2);

        // Call function
        if (lua_pcall(L, 1, 1, 0) != 0) {
            std::string error = lua_tostring(L, -1);
            m_cybersim->AddGlobalLog("Lua Error in " + std::string(functionName) + ": " + error);
            lua_pop(L, 2);
            return false;
        }

        bool result = lua_toboolean(L, -1);
        lua_pop(L, 2);
        return result;
    }

public:
    // ITechnique interface implementation
    std::string GetID() const override { return m_id; }
    std::string GetName() const override { return m_name; }
    std::string GetTactic() const override { return m_tactic; }
    std::string GetDescription() const override { return m_description; }

    bool Initialize() override {
        if (!m_loaded) return false;
        return CallLuaFunction("initialize");
    }

    void Execute() override {
        if (!m_loaded) return;
        CallLuaFunction("execute");
    }

    void Stop() override {
        if (!m_loaded) return;
        CallLuaFunction("stop");
    }

    float GetProgress() const override {
        if (!m_loaded) return 0.0f;

        lua_getglobal(L, "technique");
        lua_getfield(L, -1, "state");
        lua_getfield(L, -1, "progress");

        float progress = 0.0f;
        if (lua_isnumber(L, -1)) {
            progress = (float)lua_tonumber(L, -1);
        }

        lua_pop(L, 3);
        return progress;
    }

    std::vector<std::string> GetLogs() const override {
        std::vector<std::string> logs;
        if (!m_loaded) return logs;

        lua_getglobal(L, "technique");
        lua_getfield(L, -1, "state");
        lua_getfield(L, -1, "logs");

        if (lua_istable(L, -1)) {
            int len = lua_safe_len(L, -1);
            for (int i = 1; i <= len; i++) {
                lua_rawgeti(L, -1, i);
                if (lua_isstring(L, -1)) {
                    logs.push_back(lua_tostring(L, -1));
                }
                lua_pop(L, 1);
            }
        }

        lua_pop(L, 3);
        return logs;
    }

    bool IsRunning() const override {
        if (!m_loaded) return false;

        lua_getglobal(L, "technique");
        lua_getfield(L, -1, "state");
        lua_getfield(L, -1, "running");

        bool running = false;
        if (lua_isboolean(L, -1)) {
            running = lua_toboolean(L, -1);
        }

        lua_pop(L, 3);
        return running;
    }

    void RenderCustomUI() override {
        if (!m_loaded) {
            ImGui::Text("Script not loaded");
            return;
        }

        // Call Lua render_ui function
        lua_getglobal(L, "technique");
        lua_getfield(L, -1, "render_ui");

        if (lua_isfunction(L, -1)) {
            lua_pushvalue(L, -2); // Push self
            if (lua_pcall(L, 1, 0, 0) != 0) {
                std::string error = lua_tostring(L, -1);
                ImGui::Text("UI Error: %s", error.c_str());
                lua_pop(L, 1);
            }
        }
        else {
            ImGui::Text("No render_ui function defined");
            lua_pop(L, 1);
        }

        lua_pop(L, 1);
    }

    // Additional methods for script management
    bool ReloadScript() {
        if (L) {
            lua_close(L);
        }
        L = luaL_newstate();
        luaL_openlibs(L);
        LuaBridge::RegisterKibritAPI(L, m_cybersim);
        return LoadScript();
    }

    std::string GetScriptPath() const { return m_scriptPath; }
    bool IsLoaded() const { return m_loaded; }
};

// CyberSimLayer implementation
CyberSimLayer::CyberSimLayer() {
    AddGlobalLog("CyberSimLayer constructor started");

    LoadAllLuaScripts("scripts");

    // Initialize techniques
    AddGlobalLog("Creating technique adapters...");
    m_techniques.push_back(std::make_unique<T1055Adapter>());
    AddGlobalLog("Created T1055Adapter");

    m_techniques.push_back(std::make_unique<T1134Adapter>());
    AddGlobalLog("Created T1134Adapter");

    m_techniques.push_back(std::make_unique<T1547_001Adapter>());
    AddGlobalLog("Created T1547_001Adapter");

    m_techniques.push_back(std::make_unique<T1059_003Adapter>());
    AddGlobalLog("Created T1059_003Adapter");

    AddGlobalLog("All technique adapters created successfully");

    // Initialize all techniques during construction
    AddGlobalLog("Auto-initializing all techniques...");
    for (int i = 0; i < m_techniques.size(); i++) {
        auto& technique = m_techniques[i];
        AddGlobalLog("Auto-initializing: " + technique->GetID());

        bool result = technique->Initialize();
        if (result) {
            AddGlobalLog("Auto-init success: " + technique->GetID());
        }
        else {
            AddGlobalLog("Auto-init failed: " + technique->GetID());
        }
    }

    // Initialize UI state
    m_showStatistics = true;
    m_showAbout = false;
    m_showLogs = true;
    m_showTechniqueDetails = true;
    m_autoScroll = true;

    AddGlobalLog("CyberSim initialization complete");
}

void CyberSimLayer::LoadLuaTechnique(const std::string& scriptPath) {
    auto luaTechnique = std::make_unique<LuaTechnique>(scriptPath, this);
    if (luaTechnique->IsLoaded()) {
        m_techniques.push_back(std::move(luaTechnique));
        AddGlobalLog("Loaded Lua technique: " + scriptPath);
    }
    else {
        AddGlobalLog("Failed to load Lua technique: " + scriptPath);
    }
}

void CyberSimLayer::LoadAllLuaScripts(const std::string& directory) {
    try {
        if (std::filesystem::exists(directory)) {
            for (const auto& entry : std::filesystem::directory_iterator(directory)) {
                if (entry.path().extension() == ".lua") {
                    LoadLuaTechnique(entry.path().string());
                }
            }
        }
        else {
            AddGlobalLog("Scripts directory not found: " + directory);
        }
    }
    catch (const std::exception& e) {
        AddGlobalLog("Error scanning scripts: " + std::string(e.what()));
    }
}

void CyberSimLayer::ExportData(bool logs, bool statistics, bool configuration) {
    std::string filename = "kibrit_logs_export.txt";

    std::ofstream file(filename);
    if (!file.is_open()) {
        AddGlobalLog("Export failed: Could not create file");
        return;
    }

    file << "Kibrit Export\n";
    file << "===============\n\n";

    if (logs) {
        file << "LOGS:\n";
        file << "-----\n";
        for (const auto& log : m_globalLogs) {
            file << log << "\n";
        }
        file << "\n";
    }

    if (statistics) {
        file << "STATISTICS:\n";
        file << "-----------\n";
        file << "Session: " << m_sessionName << "\n";
        file << "Total Techniques: " << m_techniques.size() << "\n";
        file << "Log Entries: " << m_globalLogs.size() << "\n\n";
    }

    if (configuration) {
        file << "CONFIGURATION:\n";
        file << "--------------\n";
        file << "Show Statistics: " << (m_showStatistics ? "Yes" : "No") << "\n";
        file << "Show Logs: " << (m_showLogs ? "Yes" : "No") << "\n\n";
    }

    file.close();
    AddGlobalLog("Export completed: " + filename);
}

void CyberSimLayer::InitializeAllTechniques() {
    AddGlobalLog("Starting initialization of all techniques...");

    int successCount = 0;
    int failCount = 0;

    for (int i = 0; i < m_techniques.size(); i++) {
        auto& technique = m_techniques[i];

        AddGlobalLog("Initializing technique: " + technique->GetID() + " - " + technique->GetName());

        bool result = technique->Initialize();

        if (result) {
            successCount++;
            AddGlobalLog("Successfully initialized: " + technique->GetID());
        }
        else {
            failCount++;
            AddGlobalLog("Failed to initialize: " + technique->GetID());
        }
    }

    AddGlobalLog("Initialization complete. Success: " + std::to_string(successCount) +
        ", Failed: " + std::to_string(failCount));
    m_sessionModified = true;
}

void CyberSimLayer::StopAllTechniques() {
    for (auto& technique : m_techniques) {
        technique->Stop();
    }
    AddGlobalLog("All techniques stopped");
    m_sessionModified = true;
}

void CyberSimLayer::ResetAllTechniques() {
    for (auto& technique : m_techniques) {
        technique->Stop();
        // Since we don't have Reset(), we'll just stop and re-initialize
        technique->Initialize();
    }
    AddGlobalLog("All techniques reset");
    m_sessionModified = true;
}

void CyberSimLayer::NewSession() {
    StopAllTechniques();
    ResetAllTechniques();
    m_globalLogs.clear();
    m_sessionName = "New Session";
    m_sessionModified = false;
    AddGlobalLog("New session created");
}

void CyberSimLayer::AddGlobalLog(const std::string& message) {
    char timestamp[64];
    time_t now = time(0);
    struct tm timeinfo;
    localtime_s(&timeinfo, &now);
    strftime(timestamp, sizeof(timestamp), "[%H:%M:%S]", &timeinfo);

    m_globalLogs.push_back(std::string(timestamp) + " " + message);
}

void CyberSimLayer::ShowTechniqueInfo(int techniqueIndex) {
    m_selectedTechnique = techniqueIndex;
    m_showTechniqueInfo = true;
}

void CyberSimLayer::ClearLogs() {
    m_globalLogs.clear();
    AddGlobalLog("Logs cleared");
}

ITechnique* CyberSimLayer::GetTechnique(int index) {
    if (index >= 0 && index < m_techniques.size()) {
        return m_techniques[index].get();
    }
    return nullptr;
}

void CyberSimLayer::OnUIRender() {
    // Main application window
    ImGui::Begin("Kibrit - MITRE ATT&CK Educational Simulator");

    RenderHeader();
    ImGui::Separator();

    RenderTechniquesList();
    ImGui::Separator();

    if (m_showTechniqueDetails) {
        RenderSelectedTechnique();
    }

    ImGui::End();

    // Conditional windows based on menu selections
    if (m_showStatistics) {
        RenderStatisticsWindow();
    }

    if (m_showLogs) {
        RenderLogsWindow();
    }

    if (m_showAbout) {
        RenderAboutWindow();
    }

    // Settings modal
    if (m_showSettings) {
        RenderSettingsModal();
    }

    // Export modal
    if (m_showExportDialog) {
        RenderExportModal();
    }

    // Technique info modal
    if (m_showTechniqueInfo) {
        RenderTechniqueInfoModal();
    }
}

void CyberSimLayer::RenderHeader() {
    ImGui::Text("MITRE ATT&CK Educational Simulator");
    ImGui::Text("Session: %s%s", m_sessionName.c_str(), m_sessionModified ? "*" : "");

    ImGui::Spacing();

    // Global controls with status feedback
    if (ImGui::Button("Initialize All")) {
        InitializeAllTechniques();
    }
    ImGui::SameLine();
    if (ImGui::Button("Stop All")) {
        StopAllTechniques();
    }
    ImGui::SameLine();
    if (ImGui::Button("Reset All")) {
        ResetAllTechniques();
    }

    ImGui::SameLine();
    ImGui::Separator();
    ImGui::SameLine();

    // Enhanced status indicators
    int running = GetRunningTechniquesCount();
    int completed = GetCompletedTechniquesCount();
    int initialized = GetInitializedTechniquesCount();

    ImGui::Text("Initialized: %d | Running: %d | Completed: %d/%d",
        initialized, running, completed, (int)m_techniques.size());
}

int CyberSimLayer::GetInitializedTechniquesCount() const {
    int count = 0;
    for (const auto& technique : m_techniques) {
        // Check if technique has been initialized by looking at progress or logs
        if (technique->GetProgress() > 0.0f || !technique->GetLogs().empty()) {
            count++;
        }
    }
    return count;
}

void CyberSimLayer::RenderTechniquesList() {
    ImGui::Text("Available Techniques:");

    if (ImGui::BeginTable("TechniquesTable", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("ID", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Init", ImGuiTableColumnFlags_WidthFixed, 40.0f);
        ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("Progress", ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableHeadersRow();

        for (int i = 0; i < m_techniques.size(); i++) {
            ImGui::TableNextRow();

            ImGui::TableSetColumnIndex(0);
            bool isSelected = (m_selectedTechnique == i);
            if (ImGui::Selectable(m_techniques[i]->GetID().c_str(), isSelected,
                ImGuiSelectableFlags_SpanAllColumns)) {
                m_selectedTechnique = i;
            }

            ImGui::TableSetColumnIndex(1);
            ImGui::Text("%s", m_techniques[i]->GetName().c_str());

            ImGui::TableSetColumnIndex(2);
            // Show initialization status
            bool isInitialized = (m_techniques[i]->GetProgress() > 0.0f ||
                !m_techniques[i]->GetLogs().empty());
            ImGui::TextColored(isInitialized ? ImVec4(0.0f, 1.0f, 0.0f, 1.0f) :
                ImVec4(0.7f, 0.7f, 0.7f, 1.0f),
                isInitialized ? "OK" : "o");

            ImGui::TableSetColumnIndex(3);
            const char* status = m_techniques[i]->IsRunning() ? "Running" :
                (m_techniques[i]->GetProgress() >= 1.0f ? "Complete" : "Ready");
            ImVec4 color = m_techniques[i]->IsRunning() ? ImVec4(1.0f, 1.0f, 0.0f, 1.0f) :
                (m_techniques[i]->GetProgress() >= 1.0f ? ImVec4(0.0f, 1.0f, 0.0f, 1.0f) :
                    ImVec4(0.7f, 0.7f, 0.7f, 1.0f));
            ImGui::TextColored(color, "%s", status);

            ImGui::TableSetColumnIndex(4);
            float progress = m_techniques[i]->GetProgress();
            ImGui::ProgressBar(progress, ImVec2(-1, 0), "%.1f%%");
        }
        ImGui::EndTable();
    }
}

void CyberSimLayer::RenderSelectedTechnique() {
    if (m_selectedTechnique >= 0 && m_selectedTechnique < m_techniques.size()) {
        auto& technique = m_techniques[m_selectedTechnique];

        ImGui::Text("Selected: %s", technique->GetName().c_str());
        ImGui::Text("Tactic: %s", technique->GetTactic().c_str());
        ImGui::TextWrapped("Description: %s", technique->GetDescription().c_str());

        ImGui::Separator();

        // Render technique-specific UI
        technique->RenderCustomUI();
    }
}

void CyberSimLayer::RenderStatisticsWindow() {
    ImGui::Begin("Statistics", &m_showStatistics);

    ImGui::Text("Simulation Statistics");
    ImGui::Separator();

    int totalTechniques = (int)m_techniques.size();
    int runningTechniques = GetRunningTechniquesCount();
    int completedTechniques = GetCompletedTechniquesCount();

    ImGui::Text("Total Techniques: %d", totalTechniques);
    ImGui::Text("Currently Running: %d", runningTechniques);
    ImGui::Text("Completed: %d", completedTechniques);

    float overallProgress = GetOverallProgress();
    ImGui::Text("Overall Progress:");
    ImGui::ProgressBar(overallProgress, ImVec2(-1, 0), "%.1f%%");

    ImGui::Separator();

    // Performance metrics
    ImGui::Text("Session Metrics:");
    ImGui::Text("Session Duration: %.1f minutes", ImGui::GetTime() / 60.0f);
    ImGui::Text("Total Log Entries: %d", (int)m_globalLogs.size());

    ImGui::Separator();

    // Technique breakdown
    if (ImGui::CollapsingHeader("Technique Breakdown")) {
        for (const auto& technique : m_techniques) {
            ImGui::Text("%s: %.1f%% (%s)",
                technique->GetID().c_str(),
                technique->GetProgress() * 100.0f,
                technique->IsRunning() ? "Running" : "Idle");
        }
    }

    ImGui::End();
}

void CyberSimLayer::RenderLogsWindow() {
    ImGui::Begin("Global Logs", &m_showLogs);

    // Controls
    if (ImGui::Button("Clear Logs")) {
        m_globalLogs.clear();
    }
    ImGui::SameLine();
    if (ImGui::Button("Export Logs")) {
        m_showExportDialog = true;
    }
    ImGui::SameLine();
    ImGui::Checkbox("Auto-scroll", &m_autoScroll);

    ImGui::Separator();

    // Log display
    ImGui::BeginChild("LogsScrolling", ImVec2(0, 0), true);

    // Collect all logs from all techniques
    UpdateGlobalLogs();

    for (const auto& log : m_globalLogs) {
        ImGui::TextWrapped("%s", log.c_str());
    }

    if (m_autoScroll && ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) {
        ImGui::SetScrollHereY(1.0f);
    }

    ImGui::EndChild();
    ImGui::End();
}

void CyberSimLayer::RenderAboutWindow() {
    ImGui::Begin("About CyberSim", &m_showAbout);

    ImGui::Text("Kibrit v1.0");
    ImGui::Text("MITRE ATT&CK Simulator");
    ImGui::Separator();

    ImGui::TextWrapped("This application provides safe, educational demonstrations of cybersecurity attack techniques from the MITRE ATT&CK framework.");

    ImGui::Spacing();
    if (ImGui::CollapsingHeader("Purpose")) {
        ImGui::BulletText("Learn about attack techniques safely");
        ImGui::BulletText("Understand defensive strategies");
        ImGui::BulletText("Practice incident response");
        ImGui::BulletText("Build cybersecurity awareness");
    }

    if (ImGui::CollapsingHeader("Implemented Techniques")) {
        for (const auto& technique : m_techniques) {
            ImGui::BulletText("%s - %s", technique->GetID().c_str(), technique->GetName().c_str());
        }
    }

    if (ImGui::CollapsingHeader("System Information")) {
        ImGui::Text("Framework: (Dear ImGui + Vulkan)");
        ImGui::Text("Platform: Windows");
        ImGui::Text("Version: 1.0.0");
    }

    ImGui::Spacing();
    ImGui::Text("Disclaimer:");
    ImGui::TextWrapped("This tool is for educational purposes only.");

    ImGui::Spacing();
    if (ImGui::Button("Visit MITRE ATT&CK")) {
        ShellExecute(0, 0, L"https://attack.mitre.org/", 0, 0, SW_SHOW);
    }
    ImGui::SameLine();
    if (ImGui::Button("GitHub Repository")) {
        ShellExecute(0, 0, L"https://github.com/vxintelligence/kibrit", 0, 0, SW_SHOW);
    }

    ImGui::End();
}

void CyberSimLayer::RenderSettingsModal() {
    ImGui::OpenPopup("Settings");

    if (ImGui::BeginPopupModal("Settings", &m_showSettings, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("Application Settings");
        ImGui::Separator();

        // UI Settings
        if (ImGui::CollapsingHeader("User Interface")) {
            ImGui::Checkbox("Show Statistics Window", &m_showStatistics);
            ImGui::Checkbox("Show Logs Window", &m_showLogs);
            ImGui::Checkbox("Show Technique Details", &m_showTechniqueDetails);
            ImGui::Checkbox("Auto-scroll Logs", &m_autoScroll);
        }

        // Session Settings
        if (ImGui::CollapsingHeader("Session")) {
            char sessionBuffer[256];
            strcpy_s(sessionBuffer, m_sessionName.c_str());
            if (ImGui::InputText("Session Name", sessionBuffer, sizeof(sessionBuffer))) {
                m_sessionName = sessionBuffer;
                m_sessionModified = true;
            }
        }

        ImGui::Separator();

        if (ImGui::Button("Apply")) {
            m_showSettings = false;
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) {
            m_showSettings = false;
        }

        ImGui::EndPopup();
    }
}

void CyberSimLayer::RenderExportModal() {
    ImGui::OpenPopup("Export Data");

    if (ImGui::BeginPopupModal("Export Data", &m_showExportDialog, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("Choose what to export:");
        ImGui::Separator();

        static bool exportLogs = true;
        static bool exportStatistics = true;
        static bool exportConfiguration = false;

        ImGui::Checkbox("Export Logs", &exportLogs);
        ImGui::Checkbox("Export Statistics", &exportStatistics);
        ImGui::Checkbox("Export Configuration", &exportConfiguration);

        ImGui::Separator();

        // Show export location
        try {
            std::filesystem::path currentPath = std::filesystem::current_path();
            ImGui::Text("Export Location:");
            ImGui::TextWrapped("%s", currentPath.string().c_str());
        }
        catch (...) {
            ImGui::Text("Export Location: Current Directory");
        }

        ImGui::Separator();

        if (ImGui::Button("Export (Simple)")) {
            ExportData(exportLogs, exportStatistics, exportConfiguration);
            m_showExportDialog = false;
        }
        ImGui::SameLine();
        if (ImGui::Button("Export (Advanced)")) {
            ExportData(exportLogs, exportStatistics, exportConfiguration);
            m_showExportDialog = false;
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) {
            m_showExportDialog = false;
        }

        ImGui::EndPopup();
    }
}

void CyberSimLayer::RenderTechniqueInfoModal() {
    ImGui::OpenPopup("Technique Information");

    if (ImGui::BeginPopupModal("Technique Information", &m_showTechniqueInfo, ImGuiWindowFlags_AlwaysAutoResize)) {
        if (m_selectedTechnique >= 0 && m_selectedTechnique < m_techniques.size()) {
            auto& technique = m_techniques[m_selectedTechnique];

            ImGui::Text("Technique: %s", technique->GetName().c_str());
            ImGui::Text("ID: %s", technique->GetID().c_str());
            ImGui::Text("Tactic: %s", technique->GetTactic().c_str());
            ImGui::Separator();

            if (m_selectedTechnique >= 4) {
                // This is likely a Lua technique, get author info
                // We can add a method to access the author through the technique container
                ImGui::Text("Author:");
            }
            else {
                ImGui::Text("Author: System");
            }

            ImGui::Separator();

            ImGui::TextWrapped("Description: %s", technique->GetDescription().c_str());
            ImGui::Separator();

            if (ImGui::Button("View on MITRE ATT&CK")) {
                std::string url = "https://attack.mitre.org/techniques/" + technique->GetID() + "/";
                ShellExecuteA(0, 0, url.c_str(), 0, 0, SW_SHOW);
            }
        }

        ImGui::Separator();

        if (ImGui::Button("Close")) {
            m_showTechniqueInfo = false;
        }

        ImGui::EndPopup();
    }
}

int CyberSimLayer::GetRunningTechniquesCount() const {
    int count = 0;
    for (const auto& technique : m_techniques) {
        if (technique->IsRunning()) count++;
    }
    return count;
}

int CyberSimLayer::GetCompletedTechniquesCount() const {
    int count = 0;
    for (const auto& technique : m_techniques) {
        if (technique->GetProgress() >= 1.0f) count++;
    }
    return count;
}

float CyberSimLayer::GetOverallProgress() const {
    if (m_techniques.empty()) return 0.0f;

    float totalProgress = 0.0f;
    for (const auto& technique : m_techniques) {
        totalProgress += technique->GetProgress();
    }
    return totalProgress / m_techniques.size();
}

void CyberSimLayer::UpdateGlobalLogs() {
    // This would collect logs from all techniques and add them to global logs
    // Implementation depends on how you want to handle log aggregation
}

// Updated Application entry point with complete menu
Walnut::Application* Walnut::CreateApplication(int argc, char** argv) {
    Walnut::ApplicationSpecification spec;
    spec.Name = "Kibrit - MITRE ATT&CK Educational Simulator";
    spec.Width = 1400;
    spec.Height = 900;

    Walnut::Application* app = new Walnut::Application(spec);

    // Create and push the main layer
    auto cyberSimLayer = std::make_shared<CyberSimLayer>();
    app->PushLayer(cyberSimLayer);

    // Setup comprehensive menu bar
    app->SetMenubarCallback([app, cyberSimLayer]() {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("New Session", "Ctrl+N")) {
                cyberSimLayer->NewSession();
            }
            if (ImGui::MenuItem("Save Session", "Ctrl+S")) {
                // Save functionality
                cyberSimLayer->AddGlobalLog("Session saved");
            }
            if (ImGui::MenuItem("Load Session", "Ctrl+O")) {
                // Load functionality
                cyberSimLayer->ShowImportDialog();
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Export Logs", "Ctrl+E")) {
                cyberSimLayer->ShowExportDialog();
            }
            if (ImGui::MenuItem("Import Configuration")) {
                cyberSimLayer->ShowImportDialog();
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Settings", "Ctrl+,")) {
                cyberSimLayer->ShowSettings();
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Exit", "Alt+F4")) {
                app->Close();
            }
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("Techniques")) {
            if (ImGui::MenuItem("Initialize All", "Ctrl+I")) {
                cyberSimLayer->InitializeAllTechniques();
            }
            if (ImGui::MenuItem("Stop All", "Ctrl+Shift+S")) {
                cyberSimLayer->StopAllTechniques();
            }
            if (ImGui::MenuItem("Reset All", "Ctrl+R")) {
                cyberSimLayer->ResetAllTechniques();
            }
            ImGui::Separator();

            // Individual technique controls
            for (int i = 0; i < (int)cyberSimLayer->GetTechniqueCount(); i++) {
                auto* technique = cyberSimLayer->GetTechnique(i);
                if (technique) {
                    std::string label = technique->GetID() + " - " + technique->GetName();

                    if (ImGui::BeginMenu(label.c_str())) {
                        if (ImGui::MenuItem("Execute")) {
                            technique->Execute();
                        }
                        if (ImGui::MenuItem("Stop")) {
                            technique->Stop();
                        }
                        if (ImGui::MenuItem("View Details")) {
                            cyberSimLayer->ShowTechniqueInfo(i);
                        }
                        ImGui::EndMenu();
                    }
                }
            }

            ImGui::Separator();
            if (ImGui::MenuItem("Reset Progress")) {
                cyberSimLayer->ResetAllTechniques();
            }
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("View")) {
            ImGui::MenuItem("Statistics Window", nullptr, &cyberSimLayer->GetShowStatistics());
            ImGui::MenuItem("Logs Window", nullptr, &cyberSimLayer->GetShowLogs());
            ImGui::MenuItem("Technique Details", nullptr, &cyberSimLayer->GetShowTechniqueDetails());
            ImGui::Separator();
            if (ImGui::MenuItem("Reset Layout")) {
                // Reset window layout functionality
                cyberSimLayer->AddGlobalLog("Layout reset");
            }
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("Tools")) {
            if (ImGui::MenuItem("Clear All Logs")) {
                cyberSimLayer->ClearLogs();
            }
            if (ImGui::MenuItem("Generate Report")) {
                cyberSimLayer->AddGlobalLog("Report generation started");
                // Report generation functionality
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Validate Techniques")) {
                cyberSimLayer->AddGlobalLog("Technique validation started");
                // Validation functionality
            }
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("Help")) {
            if (ImGui::MenuItem("About Kibrit")) {
                cyberSimLayer->ShowAbout();
            }
            if (ImGui::MenuItem("User Guide")) {
                ShellExecute(0, 0, L"https://attack.mitre.org/", 0, 0, SW_SHOW);
            }
            if (ImGui::MenuItem("MITRE ATT&CK Reference")) {
                ShellExecute(0, 0, L"https://attack.mitre.org/", 0, 0, SW_SHOW);
            }
            if (ImGui::MenuItem("Report Issue")) {
                ShellExecute(0, 0, L"https://github.com/vxintelligence/kibrit/issues", 0, 0, SW_SHOW);
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Keyboard Shortcuts")) {
                // Show shortcuts dialog
                cyberSimLayer->AddGlobalLog("Keyboard shortcuts displayed");
            }
            ImGui::EndMenu();
        }
        });

    return app;
}