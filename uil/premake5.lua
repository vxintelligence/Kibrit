project "uil"
   kind "StaticLib"
   language "C++"
   cppdialect "C++17"
   
   files { "src/**.h", "src/**.cpp" }
   
   includedirs {
      "src",
      "../vendor/imgui",
      "../vendor/glfw/include", 
      "../vendor/stb_image",
      "%{IncludeDir.VulkanSDK}",
      "%{IncludeDir.glm}",
   }
   
   links {
       "ImGui",
       "GLFW", 
       "%{Library.Vulkan}",
   }
   
   targetdir ("bin/" .. outputdir .. "/%{prj.name}")
   objdir ("../bin-int/" .. outputdir .. "/%{prj.name}")
   
   filter "system:windows"
      systemversion "latest"
      defines { "WL_PLATFORM_WINDOWS" }
      
   filter "configurations:Debug"
      defines { "WL_DEBUG" }
      runtime "Debug"
      symbols "On"
      staticruntime "off"
      
   filter "configurations:Release"
      defines { "WL_RELEASE" }
      runtime "Release"
      optimize "On"
      symbols "On"
      staticruntime "off"
      
   filter "configurations:Dist"
      defines { "WL_DIST" }
      runtime "Release"
      optimize "On"
      symbols "Off"
      staticruntime "off"