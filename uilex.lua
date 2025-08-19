-- uilex.lua

VULKAN_SDK = os.getenv("VULKAN_SDK")

IncludeDir = {}
IncludeDir["VulkanSDK"] = "%{VULKAN_SDK}/Include"
IncludeDir["glm"] = "../vendor/glm"
IncludeDir["LuaJIT"] = "../vendor/LuaJIT/src"

LibraryDir = {}
LibraryDir["VulkanSDK"] = "%{VULKAN_SDK}/Lib"
LibraryDir["LuaJIT"] = "../vendor/LuaJIT/src"

Library = {}
Library["Vulkan"] = "%{LibraryDir.VulkanSDK}/vulkan-1.lib"

group "Dependencies"
   include "vendor/imgui"
   include "vendor/glfw"
group ""

group "Core"
include "uil"
group ""
