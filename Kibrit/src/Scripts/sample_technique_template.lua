return {
    info = {
        id = "T1055",
        name = "Process Injection (Lua)",
        tactic = "Defense Evasion",
        description = "Lua-based simulation of process injection"
    },
    
    state = {
        progress = 0.0,
        logs = {},
        running = false
    },
    
    initialize = function(self)
        kibrit.log("Initializing " .. self.info.name)
        return true
    end,
    
    execute = function(self)
        self.state.running = true
        for i = 1, 10 do
            kibrit.log("Step " .. i .. ": Simulating injection...")
            self.state.progress = i / 10.0
            kibrit.sleep(500)
            if not self.state.running then break end
        end
        self.state.running = false
        kibrit.log("Technique completed")
    end,
    
    stop = function(self)
        self.state.running = false
        kibrit.log("Technique stopped")
    end,
    
    render_ui = function(self)
        if kibrit.ui.collapsing_header(self.info.name) then
            kibrit.ui.text("Status: " .. (self.state.running and "Running" or "Ready"))
            kibrit.ui.progress_bar(self.state.progress)
            
            if not self.state.running then
                if kibrit.ui.button("Execute") then
                    self:execute()
                end
            else
                if kibrit.ui.button("Stop") then
                    self:stop()
                end
            end
        end
    end
}