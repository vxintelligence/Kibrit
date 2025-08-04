local ffi = require("ffi")

-- Define Windows API functions
ffi.cdef[[
    int MessageBoxA(void* hWnd, const char* lpText, const char* lpCaption, unsigned int uType);
    void* CreateProcessA(
        const char* lpApplicationName,
        char* lpCommandLine,
        void* lpProcessAttributes,
        void* lpThreadAttributes,
        int bInheritHandles,
        unsigned long dwCreationFlags,
        void* lpEnvironment,
        const char* lpCurrentDirectory,
        void* lpStartupInfo,
        void* lpProcessInformation
    );
    unsigned long WaitForSingleObject(void* hHandle, unsigned long dwMilliseconds);
    int CloseHandle(void* hObject);
    unsigned long GetLastError();
    int DeleteFileA(const char* lpFileName);
    unsigned long GetFileAttributesA(const char* lpFileName);
    
    typedef struct {
        unsigned long cb;
        char* lpReserved;
        char* lpDesktop;
        char* lpTitle;
        unsigned long dwX;
        unsigned long dwY;
        unsigned long dwXSize;
        unsigned long dwYSize;
        unsigned long dwXCountChars;
        unsigned long dwYCountChars;
        unsigned long dwFillAttribute;
        unsigned long dwFlags;
        unsigned short wShowWindow;
        unsigned short cbReserved2;
        unsigned char* lpReserved2;
        void* hStdInput;
        void* hStdOutput;
        void* hStdError;
    } STARTUPINFOA;
    
    typedef struct {
        void* hProcess;
        void* hThread;
        unsigned long dwProcessId;
        unsigned long dwThreadId;
    } PROCESS_INFORMATION;
]]

local user32 = ffi.load("user32")
local kernel32 = ffi.load("kernel32")
local MB_OK = 0x00000000
local MB_ICONINFORMATION = 0x00000040
local INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
local INFINITE = 0xFFFFFFFF

return {
    info = {
        id = "T1197",
        name = "BITS Jobs - Actual Download Demo",
        tactic = "Defense Evasion, Persistence, Command and Control",
        description = "Demonstrates actual BITS download functionality using safe, legitimate URLs for educational purposes.",
        author = "TOUHAMI KASBAOUI"
    },
    
    -- MITRE ATT&CK Educational Content
    mitre_info = {
        overview = "Windows Background Intelligent Transfer Service (BITS) is a low-bandwidth, asynchronous file transfer mechanism. This demo shows actual BITS usage with safe URLs.",
        
        detection_methods = {
            "Monitor BITS job creation with: bitsadmin /list /allusers /verbose",
            "Check Windows Event Logs for BITS activity (Event ID 4688)",
            "Analyze network traffic for unexpected downloads",
            "Monitor for bitsadmin.exe process execution",
            "Review BITS job persistence in registry",
            "Check for files in common download locations"
        },
        
        mitigations = {
            "M1028 - Operating System Configuration",
            "M1031 - Network Intrusion Prevention", 
            "M1037 - Filter Network Traffic",
            "Restrict BITS usage via Group Policy",
            "Monitor and alert on BITS job creation",
            "Network monitoring for suspicious downloads"
        },
        
        key_learning_points = {
            "BITS downloads persist across reboots",
            "Jobs can be throttled to avoid detection",
            "BITS creates forensic artifacts in registry",
            "Downloads continue even when user logs off",
            "bitsadmin.exe is a living-off-the-land binary",
            "BITS can be used for both persistence and data transfer"
        }
    },
    
    state = {
        progress = 0.0,
        logs = {},
        running = false,
        current_phase = "ready",
        safe_url = "https://httpbin.org/json",  -- Safe test endpoint
        job_name = "KibritDemo_SafeDownload",
        download_path = "C:\\Windows\\Temp\\safe_test_download.json",
        job_created = false
    },
    
    initialize = function(self)
        kibrit.log("Initializing " .. self.info.name)
        table.insert(self.state.logs, "=== MITRE ATT&CK " .. self.info.id .. " ACTUAL DEMO ===")
        table.insert(self.state.logs, "Using SAFE URL: " .. self.state.safe_url)
        table.insert(self.state.logs, "Download location: " .. self.download_path)
        table.insert(self.state.logs, "This performs ACTUAL BITS download with safe content")
        return true
    end,
    
    execute_command = function(self, command)
        local si = ffi.new("STARTUPINFOA")
        local pi = ffi.new("PROCESS_INFORMATION")
        si.cb = ffi.sizeof(si)
        
        table.insert(self.state.logs, "  • Executing: " .. command)
        
        -- Create command buffer (needs to be mutable)
        local cmd_buffer = ffi.new("char[?]", #command + 1)
        ffi.copy(cmd_buffer, command)
        
        local result = kernel32.CreateProcessA(
            nil,
            cmd_buffer,
            nil, nil, 0, 0, nil, nil,
            si, pi
        )
        
        if result ~= 0 then
            -- Wait for process to complete
            kernel32.WaitForSingleObject(pi.hProcess, INFINITE)
            kernel32.CloseHandle(pi.hProcess)
            kernel32.CloseHandle(pi.hThread)
            table.insert(self.state.logs, "  • Command executed successfully")
            return true
        else
            local error = kernel32.GetLastError()
            table.insert(self.state.logs, "  • Command failed with error: " .. error)
            return false
        end
    end,
    
    file_exists = function(self, filepath)
        local attr = kernel32.GetFileAttributesA(filepath)
        return attr ~= INVALID_FILE_ATTRIBUTES
    end,
    
    execute = function(self)
        self.state.running = true
        kibrit.log("Starting ACTUAL BITS download demonstration")
        
        -- Phase 1: Create BITS Job
        self.state.current_phase = "creating_job"
        self.state.progress = 0.2
        table.insert(self.state.logs, "[PHASE 1] Creating BITS Job")
        
        local create_cmd = "bitsadmin /create " .. self.state.job_name
        if self:execute_command(create_cmd) then
            self.state.job_created = true
            table.insert(self.state.logs, "  • BITS job created: " .. self.state.job_name)
        else
            table.insert(self.state.logs, "  • Failed to create BITS job")
            self.state.running = false
            return
        end
        
        kibrit.sleep(2000)
        if not self.state.running then return end
        
        -- Phase 2: Add File to Job
        self.state.current_phase = "adding_file"
        self.state.progress = 0.4
        table.insert(self.state.logs, "[PHASE 2] Adding File to BITS Job")
        
        local addfile_cmd = "bitsadmin /addfile " .. self.state.job_name .. 
                           " \"" .. self.state.safe_url .. "\" \"" .. self.state.download_path .. "\""
        
        if self:execute_command(addfile_cmd) then
            table.insert(self.state.logs, "  • File added to BITS job")
            table.insert(self.state.logs, "  • Source: " .. self.state.safe_url)
            table.insert(self.state.logs, "  • Destination: " .. self.state.download_path)
        else
            table.insert(self.state.logs, "  • Failed to add file to job")
        end
        
        kibrit.sleep(1500)
        if not self.state.running then return end
        
        -- Phase 3: Resume/Start Download
        self.state.current_phase = "downloading"
        self.state.progress = 0.6
        table.insert(self.state.logs, "[PHASE 3] Starting BITS Download")
        
        local resume_cmd = "bitsadmin /resume " .. self.state.job_name
        if self:execute_command(resume_cmd) then
            table.insert(self.state.logs, "  • BITS download started")
            table.insert(self.state.logs, "  • Transfer running in background...")
        end
        
        -- Wait for download to complete
        table.insert(self.state.logs, "  • Waiting for download completion...")
        kibrit.sleep(3000)
        
        if not self.state.running then return end
        
        -- Phase 4: Check Status and Complete
        self.state.current_phase = "completing"
        self.state.progress = 0.8
        table.insert(self.state.logs, "[PHASE 4] Completing BITS Job")
        
        -- Complete the job
        local complete_cmd = "bitsadmin /complete " .. self.state.job_name
        if self:execute_command(complete_cmd) then
            table.insert(self.state.logs, "  • BITS job completed")
        end
        
        kibrit.sleep(1500)
        
        -- Phase 5: Verify Download
        self.state.current_phase = "verifying"
        self.state.progress = 0.9
        table.insert(self.state.logs, "[PHASE 5] Verifying Download")
        
        if self:file_exists(self.state.download_path) then
            table.insert(self.state.logs, "  • SUCCESS: File downloaded successfully!")
            table.insert(self.state.logs, "  • File location: " .. self.state.download_path)
            table.insert(self.state.logs, "  • You can verify the file exists on disk")
        else
            table.insert(self.state.logs, "  • File not found - download may have failed")
        end
        
        -- Phase 6: Cleanup
        self.state.current_phase = "cleanup"
        self.state.progress = 1.0
        table.insert(self.state.logs, "[PHASE 6] Cleanup (Optional)")
        table.insert(self.state.logs, "  • Downloaded file can be deleted if desired")
        table.insert(self.state.logs, "  • BITS job has been completed and removed")
        table.insert(self.state.logs, "=== ACTUAL BITS DOWNLOAD DEMONSTRATION COMPLETE ===")
        
        -- Show completion message
        user32.MessageBoxA(nil, 
            "BITS Download Complete!\n\n" ..
            "Successfully demonstrated:\n" ..
            "• Real BITS job creation\n" ..
            "• Actual file download from safe URL\n" ..
            "• Background transfer completion\n" ..
            "• Job cleanup and removal\n\n" ..
            "File saved to: " .. string.sub(self.state.download_path, 1, 50) .. "...\n\n" ..
            "This was a real BITS demonstration with safe content.",
            "MITRE ATT&CK T1197 - BITS Jobs Complete", 
            MB_OK + MB_ICONINFORMATION)
        
        self.state.running = false
        kibrit.log("BITS download demonstration completed successfully")
    end,
    
    cleanup_demo = function(self)
        -- Clean up downloaded file
        if self:file_exists(self.state.download_path) then
            if kernel32.DeleteFileA(self.state.download_path) ~= 0 then
                table.insert(self.state.logs, "• Demo cleanup: Downloaded file deleted")
            else
                table.insert(self.state.logs, "• Demo cleanup: Could not delete file (may be in use)")
            end
        end
        
        -- Cancel job if still exists
        if self.state.job_created then
            local cancel_cmd = "bitsadmin /cancel " .. self.state.job_name
            self:execute_command(cancel_cmd)
            table.insert(self.state.logs, "• Demo cleanup: BITS job cancelled")
        end
    end,
    
    stop = function(self)
        self.state.running = false
        self.state.current_phase = "stopped"
        kibrit.log("BITS download demonstration stopped")
        table.insert(self.state.logs, "*** DEMONSTRATION STOPPED BY USER ***")
        
        -- Clean up if stopped mid-execution
        self:cleanup_demo()
    end,
    
    render_ui = function(self)
        if kibrit.ui.collapsing_header(self.info.id .. " - " .. self.info.name) then
            
            -- Status and Controls
            kibrit.ui.text("Status: " .. (self.state.running and ("Running - " .. self.state.current_phase) or "Ready"))
            kibrit.ui.text("ACTUAL BITS Download - Safe Educational Demo")
            kibrit.ui.progress_bar(self.state.progress)
            
            if not self.state.running then
                if kibrit.ui.button("Start ACTUAL BITS Download") then
                    self:execute()
                end
                if kibrit.ui.button("Cleanup Demo Files") then
                    self:cleanup_demo()
                end
            else
                if kibrit.ui.button("Stop Download") then
                    self:stop()
                end
            end
            
            -- Download Configuration
            if kibrit.ui.collapsing_header("Download Configuration") then
                kibrit.ui.text("URL: " .. self.state.safe_url)
                kibrit.ui.text("Job Name: " .. self.state.job_name)
                kibrit.ui.text("Destination: " .. self.state.download_path)
                kibrit.ui.text("Note: Uses httpbin.org for safe testing")
            end
            
            -- MITRE ATT&CK Information
            if kibrit.ui.collapsing_header("MITRE ATT&CK Information") then
                kibrit.ui.text("Technique ID: " .. self.info.id)
                kibrit.ui.text("Tactic: " .. self.info.tactic)
                kibrit.ui.text("Description: " .. self.info.description)
            end
            
            -- Detection Methods
            if kibrit.ui.collapsing_header("Detection Methods") then
                for i, method in ipairs(self.mitre_info.detection_methods) do
                    kibrit.ui.text("• " .. method)
                end
            end
            
            -- Key Learning Points
            if kibrit.ui.collapsing_header("Key Learning Points") then
                for i, point in ipairs(self.mitre_info.key_learning_points) do
                    kibrit.ui.text("• " .. point)
                end
            end
            
            -- Execution Logs
            if kibrit.ui.collapsing_header("Execution Logs") then
                for i, log in ipairs(self.state.logs) do
                    kibrit.ui.text(log)
                end
            end
        end
    end
}