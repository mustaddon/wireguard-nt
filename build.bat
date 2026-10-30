:: 1) download and mount EWDK_ge_release_svc_prod1.iso
:: 2) run D:\LaunchBuildEnv.cmd
:: 3) run build.bat

set BUILDDIR=%~dp0

Msbuild "%BUILDDIR%driver\driver.vcxproj" /p:configuration=release /p:platform=x64
Msbuild "%BUILDDIR%api\api.vcxproj" /p:configuration=release /p:platform=x64