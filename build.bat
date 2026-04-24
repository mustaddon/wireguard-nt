set BUILDDIR=%~dp0

Msbuild "%BUILDDIR%driver\driver.vcxproj" /p:configuration=release /p:platform=x64
Msbuild "%BUILDDIR%api\api.vcxproj" /p:configuration=release /p:platform=x64