// Application.h
#pragma once

#include "uil/Application.h"
#include "uil/EntryPoint.h"
#include "uil/Image.h"

// Don't include imgui.h directly - use Walnut's includes
// #include "imgui.h" // Remove this line if present

#include <memory>
#include <vector>
#include <map>
#include <string>
#include <functional>

namespace CyberSim {

    // Forward declarations
    class ITechnique;
    class SimulationEngine;
    class NetworkTopology;

    struct TechniqueInfo {
        std::string id;
        std::string name;
        std::string tactic;
        std::string description;
        std::vector<std::string> platforms;
        std::string dataSource;
        bool isActive = false;
        float progress = 0.0f;
    };

    struct SimulationState {
        bool isRunning = false;
        float overallProgress = 0.0f;
        std::vector<std::string> logs;
        std::map<std::string, TechniqueInfo> activeTechniques;
        int compromisedHosts = 0;
        int totalHosts = 10;
    };

    class CyberSimApp : public Walnut::Application {
    public:
        CyberSimApp();
        virtual ~CyberSimApp() = default;

        virtual void OnUIRender() override;

    private:
        void RenderMainMenuBar();
        void RenderTechniqueLibrary();
        void RenderSimulationDashboard();
        void RenderNetworkTopology();
        void RenderTechniqueLogs();
        void RenderTechniqueDetails();

        void LoadTechniques();
        void StartSimulation();
        void StopSimulation();
        void UpdateSimulation();

        // UI State
        bool m_showTechniqueLibrary = true;
        bool m_showSimulationDashboard = true;
        bool m_showNetworkTopology = true;
        bool m_showTechniqueLogs = true;
        bool m_showTechniqueDetails = false;

        std::string m_selectedTechnique = "";
        std::string m_searchFilter = "";
        std::string m_tacticFilter = "All";

        // Core components
        std::unique_ptr<SimulationEngine> m_simulationEngine;
        std::map<std::string, std::unique_ptr<ITechnique>> m_techniques;
        SimulationState m_simulationState;

        // UI Resources
        std::shared_ptr<Walnut::Image> m_logoImage;
        std::shared_ptr<Walnut::Image> m_networkIcon;
        std::shared_ptr<Walnut::Image> m_threatIcon;
    };

    // Technique Plugin Interface
    class ITechnique {
    public:
        virtual ~ITechnique() = default;
        virtual TechniqueInfo GetInfo() const = 0;
        virtual bool Initialize() = 0;
        virtual void Execute() = 0;
        virtual void Stop() = 0;
        virtual float GetProgress() const = 0;
        virtual std::vector<std::string> GetLogs() const = 0;
        virtual void RenderCustomUI() {}
    };

    // Plugin Registration System
    class TechniqueRegistry {
    public:
        static TechniqueRegistry& Instance();

        template<typename T>
        void RegisterTechnique(const std::string& id) {
            m_creators[id] = []() -> std::unique_ptr<ITechnique> {
                return std::make_unique<T>();
                };
        }

        std::unique_ptr<ITechnique> CreateTechnique(const std::string& id);
        std::vector<std::string> GetRegisteredTechniques() const;

    private:
        std::map<std::string, std::function<std::unique_ptr<ITechnique>()>> m_creators;
    };

    // Simulation Engine
    class SimulationEngine {
    public:
        SimulationEngine();
        ~SimulationEngine() = default;

        void Start();
        void Stop();
        void Update();
        bool IsRunning() const { return m_isRunning; }

        void AddTechnique(const std::string& id, std::unique_ptr<ITechnique> technique);
        void RemoveTechnique(const std::string& id);

        const SimulationState& GetState() const { return m_state; }

    private:
        bool m_isRunning = false;
        SimulationState m_state;
        std::map<std::string, std::unique_ptr<ITechnique>> m_activeTechniques;
        std::chrono::steady_clock::time_point m_lastUpdate;
    };
}

// main.cpp
#include "Application.h"

Walnut::Application* Walnut::CreateApplication(int argc, char** argv) {
    Walnut::ApplicationSpecification spec;
    spec.Name = "CyberSim - MITRE ATT&CK Simulator";
    spec.Width = 1600;
    spec.Height = 900;

    return new CyberSim::CyberSimApp();
}

// Application.cpp
#include "Application.h"
#include "Walnut/UI/UI.h"
#include "imgui.h"

#include <algorithm>
#include <chrono>

namespace CyberSim {

    CyberSimApp::CyberSimApp() {
        // Initialize simulation engine
        m_simulationEngine = std::make_unique<SimulationEngine>();

        // Load techniques from plugins
        LoadTechniques();

        // Load UI resources
        // m_logoImage = std::make_shared<Walnut::Image>("assets/logo.png");
        // m_networkIcon = std::make_shared<Walnut::Image>("assets/network.png");
        // m_threatIcon = std::make_shared<Walnut::Image>("assets/threat.png");
    }

    void CyberSimApp::OnUIRender() {
        // Update simulation
        if (m_simulationEngine->IsRunning()) {
            m_simulationEngine->Update();
            m_simulationState = m_simulationEngine->GetState();
        }

        RenderMainMenuBar();

        // Create dockspace
        ImGuiDockNodeFlags dockspace_flags = ImGuiDockNodeFlags_None;
        ImGuiWindowFlags window_flags = ImGuiWindowFlags_MenuBar | ImGuiWindowFlags_NoDocking;

        const ImGuiViewport* viewport = ImGui::GetMainViewport();
        ImGui::SetNextWindowPos(viewport->WorkPos);
        ImGui::SetNextWindowSize(viewport->WorkSize);
        ImGui::SetNextWindowViewport(viewport->ID);

        ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
        window_flags |= ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove;
        window_flags |= ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus;

        ImGui::Begin("DockSpace", nullptr, window_flags);
        ImGui::PopStyleVar(2);

        ImGuiID dockspace_id = ImGui::GetID("CyberSimDockSpace");
        ImGui::DockSpace(dockspace_id, ImVec2(0.0f, 0.0f), dockspace_flags);

        // Render panels
        if (m_showTechniqueLibrary) RenderTechniqueLibrary();
        if (m_showSimulationDashboard) RenderSimulationDashboard();
        if (m_showNetworkTopology) RenderNetworkTopology();
        if (m_showTechniqueLogs) RenderTechniqueLogs();
        if (m_showTechniqueDetails) RenderTechniqueDetails();

        ImGui::End();
    }

    void CyberSimApp::RenderMainMenuBar() {
        if (ImGui::BeginMainMenuBar()) {
            if (ImGui::BeginMenu("File")) {
                if (ImGui::MenuItem("New Simulation")) {
                    StopSimulation();
                }
                if (ImGui::MenuItem("Load Scenario")) {
                    // TODO: Load scenario from file
                }
                if (ImGui::MenuItem("Save Scenario")) {
                    // TODO: Save current scenario
                }
                ImGui::Separator();
                if (ImGui::MenuItem("Exit")) {
                    Walnut::Application::Get().Close();
                }
                ImGui::EndMenu();
            }

            if (ImGui::BeginMenu("Simulation")) {
                if (ImGui::MenuItem("Start", nullptr, false, !m_simulationState.isRunning)) {
                    StartSimulation();
                }
                if (ImGui::MenuItem("Stop", nullptr, false, m_simulationState.isRunning)) {
                    StopSimulation();
                }
                if (ImGui::MenuItem("Reset")) {
                    StopSimulation();
                    // Reset simulation state
                }
                ImGui::EndMenu();
            }

            if (ImGui::BeginMenu("View")) {
                ImGui::MenuItem("Technique Library", nullptr, &m_showTechniqueLibrary);
                ImGui::MenuItem("Simulation Dashboard", nullptr, &m_showSimulationDashboard);
                ImGui::MenuItem("Network Topology", nullptr, &m_showNetworkTopology);
                ImGui::MenuItem("Technique Logs", nullptr, &m_showTechniqueLogs);
                ImGui::MenuItem("Technique Details", nullptr, &m_showTechniqueDetails);
                ImGui::EndMenu();
            }

            if (ImGui::BeginMenu("Help")) {
                if (ImGui::MenuItem("About")) {
                    // TODO: Show about dialog
                }
                if (ImGui::MenuItem("MITRE ATT&CK Documentation")) {
                    // TODO: Open browser to MITRE ATT&CK
                }
                ImGui::EndMenu();
            }

            ImGui::EndMainMenuBar();
        }
    }

    void CyberSimApp::RenderTechniqueLibrary() {
        ImGui::Begin("Technique Library", &m_showTechniqueLibrary);

        // Search and filter controls
        ImGui::Text("Search Techniques:");
        char searchBuffer[256];
        strcpy_s(searchBuffer, m_searchFilter.c_str());
        if (ImGui::InputText("##search", searchBuffer, sizeof(searchBuffer))) {
            m_searchFilter = searchBuffer;
        }

        ImGui::SameLine();
        const char* tactics[] = { "All", "Initial Access", "Execution", "Persistence", "Privilege Escalation",
                                 "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
                                 "Collection", "Command and Control", "Exfiltration", "Impact" };

        if (ImGui::BeginCombo("Tactic", m_tacticFilter.c_str())) {
            for (const char* tactic : tactics) {
                bool selected = (m_tacticFilter == tactic);
                if (ImGui::Selectable(tactic, selected)) {
                    m_tacticFilter = tactic;
                }
                if (selected) ImGui::SetItemDefaultFocus();
            }
            ImGui::EndCombo();
        }

        ImGui::Separator();

        // Technique list
        if (ImGui::BeginTable("TechniqueTable", 4, ImGuiTableFlags_Resizable | ImGuiTableFlags_Sortable | ImGuiTableFlags_ScrollY)) {
            ImGui::TableSetupColumn("ID", ImGuiTableColumnFlags_WidthFixed, 80.0f);
            ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Tactic", ImGuiTableColumnFlags_WidthFixed, 120.0f);
            ImGui::TableSetupColumn("Actions", ImGuiTableColumnFlags_WidthFixed, 100.0f);
            ImGui::TableHeadersRow();

            // Sample techniques (in real implementation, load from registry)
            static std::vector<TechniqueInfo> sampleTechniques = {
                {"T1566", "Phishing", "Initial Access", "Adversaries may send phishing messages to gain access to victim systems.", {"Windows", "macOS", "Linux"}, "Email Gateway"},
                {"T1059", "Command and Scripting Interpreter", "Execution", "Adversaries may abuse command and script interpreters to execute commands.", {"Windows", "macOS", "Linux"}, "Process monitoring"},
                {"T1055", "Process Injection", "Defense Evasion", "Adversaries may inject code into processes to evade process-based defenses.", {"Windows", "macOS", "Linux"}, "Process monitoring"},
                {"T1003", "OS Credential Dumping", "Credential Access", "Adversaries may attempt to dump credentials to obtain account login information.", {"Windows", "macOS", "Linux"}, "Authentication logs"}
            };

            for (const auto& technique : sampleTechniques) {
                // Apply filters
                if (!m_searchFilter.empty() &&
                    technique.name.find(m_searchFilter) == std::string::npos &&
                    technique.id.find(m_searchFilter) == std::string::npos) {
                    continue;
                }

                if (m_tacticFilter != "All" && technique.tactic != m_tacticFilter) {
                    continue;
                }

                ImGui::TableNextRow();

                ImGui::TableNextColumn();
                ImGui::Text("%s", technique.id.c_str());

                ImGui::TableNextColumn();
                if (ImGui::Selectable(technique.name.c_str(), m_selectedTechnique == technique.id, ImGuiSelectableFlags_SpanAllColumns)) {
                    m_selectedTechnique = technique.id;
                    m_showTechniqueDetails = true;
                }

                ImGui::TableNextColumn();
                ImGui::Text("%s", technique.tactic.c_str());

                ImGui::TableNextColumn();
                if (ImGui::Button(("Add##" + technique.id).c_str())) {
                    // Add technique to simulation
                    auto it = m_techniques.find(technique.id);
                    if (it != m_techniques.end()) {
                        // Clone technique for simulation
                        // m_simulationEngine->AddTechnique(technique.id, std::move(clonedTechnique));
                    }
                }
            }

            ImGui::EndTable();
        }

        ImGui::End();
    }

    void CyberSimApp::RenderSimulationDashboard() {
        ImGui::Begin("Simulation Dashboard", &m_showSimulationDashboard);

        // Status indicators
        ImGui::Text("Simulation Status: %s", m_simulationState.isRunning ? "RUNNING" : "STOPPED");
        if (m_simulationState.isRunning) {
            ImGui::SameLine();
            ImGui::PushStyleColor(ImGuiCol_PlotHistogram, ImVec4(0.2f, 0.8f, 0.2f, 1.0f));
            ImGui::ProgressBar(m_simulationState.overallProgress, ImVec2(-1, 0), "");
            ImGui::PopStyleColor();
        }

        ImGui::Separator();

        // Control buttons
        if (!m_simulationState.isRunning) {
            if (ImGui::Button("Start Simulation", ImVec2(120, 30))) {
                StartSimulation();
            }
        }
        else {
            if (ImGui::Button("Stop Simulation", ImVec2(120, 30))) {
                StopSimulation();
            }
        }

        ImGui::SameLine();
        if (ImGui::Button("Reset", ImVec2(80, 30))) {
            StopSimulation();
            // Reset state
        }

        ImGui::Separator();

        // Statistics
        ImGui::Text("Network Compromise:");
        ImGui::Indent();
        ImGui::Text("Compromised Hosts: %d / %d", m_simulationState.compromisedHosts, m_simulationState.totalHosts);
        float compromiseRatio = (float)m_simulationState.compromisedHosts / m_simulationState.totalHosts;
        ImGui::PushStyleColor(ImGuiCol_PlotHistogram, ImVec4(0.8f, 0.2f, 0.2f, 1.0f));
        ImGui::ProgressBar(compromiseRatio, ImVec2(-1, 0), "");
        ImGui::PopStyleColor();
        ImGui::Unindent();

        ImGui::Text("Active Techniques: %zu", m_simulationState.activeTechniques.size());

        // Active techniques list
        if (!m_simulationState.activeTechniques.empty()) {
            ImGui::Separator();
            ImGui::Text("Running Techniques:");

            for (const auto& [id, info] : m_simulationState.activeTechniques) {
                ImGui::Bullet();
                ImGui::Text("%s - %s", id.c_str(), info.name.c_str());
                ImGui::SameLine();
                ImGui::PushStyleColor(ImGuiCol_PlotHistogram, ImVec4(0.2f, 0.6f, 0.8f, 1.0f));
                ImGui::ProgressBar(info.progress, ImVec2(100, 0), "");
                ImGui::PopStyleColor();
            }
        }

        ImGui::End();
    }

    void CyberSimApp::RenderNetworkTopology() {
        ImGui::Begin("Network Topology", &m_showNetworkTopology);

        // This would render a visual network topology
        // For now, showing a placeholder
        ImDrawList* draw_list = ImGui::GetWindowDrawList();
        ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
        ImVec2 canvas_size = ImGui::GetContentRegionAvail();

        if (canvas_size.x < 50.0f) canvas_size.x = 50.0f;
        if (canvas_size.y < 50.0f) canvas_size.y = 50.0f;

        // Draw network nodes
        ImVec2 center = ImVec2(canvas_pos.x + canvas_size.x * 0.5f, canvas_pos.y + canvas_size.y * 0.5f);

        // Central server
        ImU32 serverColor = m_simulationState.compromisedHosts > 0 ? IM_COL32(255, 100, 100, 255) : IM_COL32(100, 255, 100, 255);
        draw_list->AddCircleFilled(center, 30.0f, serverColor);
        draw_list->AddText(ImVec2(center.x - 25, center.y - 5), IM_COL32(255, 255, 255, 255), "Server");

        // Client nodes
        const int numClients = 6;
        for (int i = 0; i < numClients; i++) {
            float angle = (i / (float)numClients) * 2.0f * 3.14159f;
            ImVec2 clientPos = ImVec2(
                center.x + cosf(angle) * 100.0f,
                center.y + sinf(angle) * 100.0f
            );

            ImU32 clientColor = (i < m_simulationState.compromisedHosts) ? IM_COL32(255, 100, 100, 255) : IM_COL32(100, 200, 255, 255);
            draw_list->AddCircleFilled(clientPos, 20.0f, clientColor);
            draw_list->AddLine(center, clientPos, IM_COL32(200, 200, 200, 255), 2.0f);

            char label[16];
            sprintf_s(label, "PC%d", i + 1);
            draw_list->AddText(ImVec2(clientPos.x - 15, clientPos.y - 5), IM_COL32(255, 255, 255, 255), label);
        }

        ImGui::InvisibleButton("canvas", canvas_size);

        ImGui::End();
    }

    void CyberSimApp::RenderTechniqueLogs() {
        ImGui::Begin("Technique Logs", &m_showTechniqueLogs);

        if (ImGui::Button("Clear Logs")) {
            m_simulationState.logs.clear();
        }

        ImGui::Separator();

        // Auto-scroll to bottom
        if (ImGui::BeginChild("LogsScrolling", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar)) {
            for (const auto& log : m_simulationState.logs) {
                ImGui::TextWrapped("%s", log.c_str());
            }

            if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) {
                ImGui::SetScrollHereY(1.0f);
            }
        }
        ImGui::EndChild();

        ImGui::End();
    }

    void CyberSimApp::RenderTechniqueDetails() {
        if (m_selectedTechnique.empty()) return;

        ImGui::Begin("Technique Details", &m_showTechniqueDetails);

        // Display detailed information about selected technique
        ImGui::Text("Technique ID: %s", m_selectedTechnique.c_str());
        ImGui::Separator();

        // This would show detailed technique information
        // Implementation would load from technique plugin

        ImGui::End();
    }

    void CyberSimApp::LoadTechniques() {
        // In a real implementation, this would:
        // 1. Scan plugins directory
        // 2. Load technique DLLs/shared libraries
        // 3. Register techniques with the registry

        // For now, we'll register some sample techniques
        auto& registry = TechniqueRegistry::Instance();
        // registry.RegisterTechnique<TechniqueT1566>("T1566");
        // registry.RegisterTechnique<TechniqueT1059>("T1059");
        // etc.
    }

    void CyberSimApp::StartSimulation() {
        m_simulationEngine->Start();
        m_simulationState.logs.push_back("[INFO] Simulation started");
    }

    void CyberSimApp::StopSimulation() {
        m_simulationEngine->Stop();
        m_simulationState.logs.push_back("[INFO] Simulation stopped");
        m_simulationState.isRunning = false;
    }

    // TechniqueRegistry Implementation
    TechniqueRegistry& TechniqueRegistry::Instance() {
        static TechniqueRegistry instance;
        return instance;
    }

    std::unique_ptr<ITechnique> TechniqueRegistry::CreateTechnique(const std::string& id) {
        auto it = m_creators.find(id);
        if (it != m_creators.end()) {
            return it->second();
        }
        return nullptr;
    }

    std::vector<std::string> TechniqueRegistry::GetRegisteredTechniques() const {
        std::vector<std::string> techniques;
        for (const auto& [id, creator] : m_creators) {
            techniques.push_back(id);
        }
        return techniques;
    }

    // SimulationEngine Implementation
    SimulationEngine::SimulationEngine() {
        m_lastUpdate = std::chrono::steady_clock::now();
    }

    void SimulationEngine::Start() {
        m_isRunning = true;
        m_state.isRunning = true;
        m_lastUpdate = std::chrono::steady_clock::now();

        // Initialize active techniques
        for (auto& [id, technique] : m_activeTechniques) {
            technique->Initialize();
        }
    }

    void SimulationEngine::Stop() {
        m_isRunning = false;
        m_state.isRunning = false;

        // Stop active techniques
        for (auto& [id, technique] : m_activeTechniques) {
            technique->Stop();
        }
    }

    void SimulationEngine::Update() {
        if (!m_isRunning) return;

        auto now = std::chrono::steady_clock::now();
        auto deltaTime = std::chrono::duration_cast<std::chrono::milliseconds>(now - m_lastUpdate).count();

        if (deltaTime >= 100) { // Update every 100ms
            // Update techniques
            for (auto& [id, technique] : m_activeTechniques) {
                // Update technique progress and logs
                float progress = technique->GetProgress();
                m_state.activeTechniques[id].progress = progress;

                auto logs = technique->GetLogs();
                for (const auto& log : logs) {
                    m_state.logs.push_back("[" + id + "] " + log);
                }
            }

            // Update overall progress
            float totalProgress = 0.0f;
            for (const auto& [id, info] : m_state.activeTechniques) {
                totalProgress += info.progress;
            }
            m_state.overallProgress = m_state.activeTechniques.empty() ? 0.0f : totalProgress / m_state.activeTechniques.size();

            // Simulate network compromise
            m_state.compromisedHosts = (int)(m_state.overallProgress * m_state.totalHosts);

            m_lastUpdate = now;
        }
    }

    void SimulationEngine::AddTechnique(const std::string& id, std::unique_ptr<ITechnique> technique) {
        m_activeTechniques[id] = std::move(technique);
        m_state.activeTechniques[id] = m_activeTechniques[id]->GetInfo();
    }

    void SimulationEngine::RemoveTechnique(const std::string& id) {
        auto it = m_activeTechniques.find(id);
        if (it != m_activeTechniques.end()) {
            it->second->Stop();
            m_activeTechniques.erase(it);
            m_state.activeTechniques.erase(id);
        }
    }
}