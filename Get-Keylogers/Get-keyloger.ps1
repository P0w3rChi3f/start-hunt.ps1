get-item HKCU:\Software\Microsoft\Windows\CurrentVersion\Run

Get-CimInstance Win32_Process | Where-Object {$_.name -match "key"} | Select-Object Name, Path

(Get-Content c:\windows\keyX.exe | Select-String -Pattern "teeamware.log" -Context (5,5))

Compare-Object (Get-ItemProperty $env:APPDATA\teeamware.log).LastWriteTime (Get-ItemProperty $env:LOCALAPPDATA\Microsoft\advkey.log).LastWriteTime -IncludeEqual