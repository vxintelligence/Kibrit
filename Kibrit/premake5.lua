project "Kibrit"
   kind "ConsoleApp"
   language "C++"
   cppdialect "C++17"
   staticruntime "off"
   
   -- Use consistent targetdir (remove the duplicate)
   targetdir ("../bin/" .. outputdir .. "/%{prj.name}")
   objdir ("../bin-int/" .. outputdir .. "/%{prj.name}")
   
   files { "src/**.h", "src/**.cpp" }
   
   includedirs
   {
      "../vendor/imgui",
      "../vendor/glfw/include",
      "../uil/src",
      "%{IncludeDir.VulkanSDK}",
      "%{IncludeDir.glm}",
      "%{IncludeDir.LuaJIT}",
   }
   
   libdirs
   {
      "%{LibraryDir.LuaJIT}"
   }
   
   links
   {
      "uil"
   }
   
   filter "system:windows"
      systemversion "latest"
      defines { "WL_PLATFORM_WINDOWS" }
      
   filter "configurations:Debug"
      defines { "WL_DEBUG" }
      runtime "Debug"
      symbols "On"
      
   filter "configurations:Release"
      defines { "WL_RELEASE" }
      runtime "Release"
      optimize "On"
      symbols "On"
      
   filter "configurations:Dist"
      kind "WindowedApp"
      defines { "WL_DIST" }
      runtime "Release"
      optimize "On"
      symbols "Off"
