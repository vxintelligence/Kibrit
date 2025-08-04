local ffi = require("ffi")

-- Define Windows API functions
ffi.cdef[[
    int MessageBoxA(void* hWnd, const char* lpText, const char* lpCaption, unsigned int uType);
]]

local user32 = ffi.load("user32")
local MB_OK = 0x00000000
local MB_ICONINFORMATION = 0x00000040

return {
    info = {
        id = "T10551",
        name = "Process Injection",
        tactic = "Defense Evasion",
        description = "Adversaries may inject code into processes in order to evade process-based defenses or elevate privileges.",
        author = "TOUHAMI KASBAOUI"
    },
    
    -- MITRE ATT&CK Educational Content
    mitre_info = {
        overview = "Process injection is a method of executing arbitrary code in the address space of a separate live process. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges.",
        
        sub_techniques = {
            "T1055.001 - Dynamic-link Library Injection",
            "T1055.002 - Portable Executable Injection", 
        },
        
        detection_methods = {
            "Monitor for suspicious process behavior",
            "Analyze memory artifacts and process memory space",
            "Monitor for malicious usage of system calls",
            "Check for unexpected process relationships",
            "Monitor API calls like CreateRemoteThread, WriteProcessMemory",
            "Use behavioral analysis to detect injection patterns",
            "Monitor for DLL loads in unusual processes"
        },
        
        mitigations = {
            "M1040 - Behavior Prevention on Endpoint",
            "M1026 - Privileged Account Management", 
            "Application Control and Whitelisting",
            "Control Flow Integrity (CFI)",
            "Data Execution Prevention (DEP)",
            "Address Space Layout Randomization (ASLR)"
        },
        
        key_learning_points = {
            "Process injection allows malware to hide within legitimate processes",
            "Multiple techniques exist, each with different detection signatures",
            "Understanding memory layout is crucial for both attack and defense",
            "Modern OS protections make injection more difficult but not impossible",
            "Detection requires monitoring both API calls and behavioral patterns",
            "Prevention relies on multiple layers of security controls"
        },
        
        real_world_examples = {
            "APT groups use DLL injection to maintain persistence",
            "Banking trojans inject into browser processes to steal credentials",
            "Rootkits use process hollowing to replace legitimate process memory",
            "Living-off-the-land attacks inject into system processes like svchost.exe"
        }
    },
    
    state = {
        progress = 0.0,
        logs = {},
        running = false,
        current_phase = "ready"
    },
    
    initialize = function(self)
        kibrit.log("Initializing " .. self.info.name .. " educational simulation")
        table.insert(self.state.logs, "=== MITRE ATT&CK " .. self.info.id .. " Educational Demo ===")
        table.insert(self.state.logs, "Technique: " .. self.info.name)
        table.insert(self.state.logs, "Tactic: " .. self.info.tactic)
        table.insert(self.state.logs, "This is a SAFE educational simulation only")
        return true
    end,
    
    execute = function(self)
        self.state.running = true
        kibrit.log("Starting educational simulation of " .. self.info.name)
        
        -- Phase 1: Target Process Identification
        self.state.current_phase = "identification"
        self.state.progress = 0.1
        table.insert(self.state.logs, "[PHASE 1] Target Process Identification")
        table.insert(self.state.logs, "  • Scanning for suitable target processes...")
        table.insert(self.state.logs, "  • Looking for processes with appropriate privileges")
        table.insert(self.state.logs, "  • Educational Note: Attackers typically target long-running processes")
        kibrit.sleep(1500)
        
        if not self.state.running then return end
        
        -- Phase 2: Memory Allocation
        self.state.current_phase = "allocation" 
        self.state.progress = 0.3
        table.insert(self.state.logs, "[PHASE 2] Memory Allocation Simulation")
        table.insert(self.state.logs, "  • Simulating VirtualAllocEx API call")
        table.insert(self.state.logs, "  • Allocating memory in target process space")
        table.insert(self.state.logs, "  • Educational Note: This step is often detected by EDR solutions")
        kibrit.sleep(1500)
        
        if not self.state.running then return end
        
        -- Phase 3: Code Writing
        self.state.current_phase = "writing"
        self.state.progress = 0.5
        table.insert(self.state.logs, "[PHASE 3] Code Writing Simulation")
        table.insert(self.state.logs, "  • Simulating WriteProcessMemory API call")
        table.insert(self.state.logs, "  • Writing payload to allocated memory")
        table.insert(self.state.logs, "  • Educational Note: Suspicious memory writes trigger alerts")
        kibrit.sleep(1500)
        
        if not self.state.running then return end
        
        -- Phase 4: Execution
        self.state.current_phase = "execution"
        self.state.progress = 0.7
        table.insert(self.state.logs, "[PHASE 4] Remote Execution Simulation")
        table.insert(self.state.logs, "  • Simulating CreateRemoteThread API call")
        table.insert(self.state.logs, "  • Starting remote thread in target process")
        table.insert(self.state.logs, "  • Educational Note: This is the most detectable phase")
        kibrit.sleep(1500)
        
        if not self.state.running then return end
        
        -- Phase 5: Completion
        self.state.current_phase = "complete"
        self.state.progress = 1.0
        table.insert(self.state.logs, "[PHASE 5] Injection Complete")
        table.insert(self.state.logs, "  • Code now running in target process context")
        table.insert(self.state.logs, "  • Gained process privileges and access")
        table.insert(self.state.logs, "=== EDUCATIONAL SIMULATION COMPLETE ===")
        
        -- Show educational summary
        user32.MessageBoxA(nil, 
            "Process Injection Simulation Complete!\n\n" ..
            "Key Learning:\n" ..
            "• 5 phases: Identify → Allocate → Write → Execute → Complete\n" ..
            "• Multiple detection opportunities exist\n" ..
            "• Modern defenses make this increasingly difficult\n\n" ..
            "This was a SAFE educational demonstration.",
            "MITRE ATT&CK T1055 - Process Injection", 
            MB_OK + MB_ICONINFORMATION)
        
        self.state.running = false
        kibrit.log("Educational simulation of " .. self.info.name .. " completed")
    end,
    
    stop = function(self)
        self.state.running = false
        self.state.current_phase = "stopped"
        kibrit.log("Process injection simulation stopped")
        table.insert(self.state.logs, "*** SIMULATION STOPPED BY USER ***")
    end,
    
    render_ui = function(self)
        if kibrit.ui.collapsing_header(self.info.id .. " - " .. self.info.name) then
            
            -- Status and Controls
            kibrit.ui.text("Status: " .. (self.state.running and ("Running - " .. self.state.current_phase) or "Ready"))
            kibrit.ui.text("Educational Simulation - SAFE DEMONSTRATION ONLY")
            kibrit.ui.progress_bar(self.state.progress)
            
            if not self.state.running then
                if kibrit.ui.button("Start Educational Demo") then
                    self:execute()
                end
            else
                if kibrit.ui.button("Stop Simulation") then
                    self:stop()
                end
            end
            
            -- MITRE ATT&CK Information
            if kibrit.ui.collapsing_header("MITRE ATT&CK Information") then
                kibrit.ui.text("Technique ID: " .. self.info.id)
                kibrit.ui.text("Tactic: " .. self.info.tactic)
                kibrit.ui.text("Description: " .. self.info.description)
                
                if kibrit.ui.collapsing_header("Overview") then
                    kibrit.ui.text(self.mitre_info.overview)
                end
            end
            
            -- Sub-Techniques
            if kibrit.ui.collapsing_header("Sub-Techniques") then
                for i, technique in ipairs(self.mitre_info.sub_techniques) do
                    kibrit.ui.text("• " .. technique)
                end
            end
            
            -- Detection Methods  
            if kibrit.ui.collapsing_header("Detection Methods") then
                for i, method in ipairs(self.mitre_info.detection_methods) do
                    kibrit.ui.text("• " .. method)
                end
            end
            
            -- Mitigations
            if kibrit.ui.collapsing_header("Mitigations") then
                for i, mitigation in ipairs(self.mitre_info.mitigations) do
                    kibrit.ui.text("• " .. mitigation)
                end
            end
            
            -- Key Learning Points
            if kibrit.ui.collapsing_header("Key Learning Points") then
                for i, point in ipairs(self.mitre_info.key_learning_points) do
                    kibrit.ui.text("• " .. point)
                end
            end
            
            -- Real-World Examples
            if kibrit.ui.collapsing_header("Real-World Examples") then
                for i, example in ipairs(self.mitre_info.real_world_examples) do
                    kibrit.ui.text("• " .. example)
                end
            end
            
            -- Execution Logs
            if kibrit.ui.collapsing_header("Simulation Logs") then
                for i, log in ipairs(self.state.logs) do
                    kibrit.ui.text(log)
                end
            end
        end
    end
}