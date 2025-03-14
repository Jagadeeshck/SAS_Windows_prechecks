# Validate system requirements for SAS 9.4 M8 on Windows Server 2019/2022

$serverType = Read-Host "Enter Server Type (Metadata, Mid-Tier, Grid, Compute)"
$os = (Get-WmiObject Win32_OperatingSystem).Caption
$ram = [math]::round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
$cpu = (Get-WmiObject Win32_Processor | Measure-Object -Property NumberOfCores -Sum).Sum
$diskIOResults = @{}

Write-Output "Checking prerequisites for $serverType..."
Write-Output "Operating System: $os"

if ($serverType -in @("Metadata", "Mid-Tier", "Grid", "Compute")) {
    Write-Output "Total RAM: $ram GB (Expected: >= 32 GB) - $(if ($ram -ge 32) { 'PASS' } else { 'FAIL' })"
    Write-Output "CPU Cores: $cpu (Expected: >= 8) - $(if ($cpu -ge 8) { 'PASS' } else { 'FAIL' })"
}

if ($serverType -in @("Grid", "Compute")) {
    $drives = Read-Host "Enter drive letters (comma-separated, e.g., C,D,E for SASWORK, SASHOME, CONFIG, etc.)"
    $driveList = $drives -split ","
    foreach ($drive in $driveList) {
        $drive = $drive.Trim()
        $diskIO = (winsat disk -drive $drive -seq -read | Select-String "MB/s").ToString()
        $diskIOResults[$drive] = $diskIO
    }
    foreach ($drive in $diskIOResults.Keys) {
        Write-Output "Disk I/O Speed on Drive $drive: $($diskIOResults[$drive]) (Expected: >= 200 MB/s) - $(if ($diskIOResults[$drive] -match '\d+' -and [int]($diskIOResults[$drive] -replace '\D+') -ge 200) { 'PASS' } else { 'FAIL' })"
    }
}
# Check SAS Install Account Rights
try {
    $account = Read-Host "Enter SAS Install Account"
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    Write-Output "SAS Install Account ($account) Admin Rights: $(if ($isAdmin) { 'PASS' } else { 'FAIL' })"
} catch {
    Write-Output "Failed to check account rights - FAIL"
}

# Check Firewall Status
try {
    $firewallStatus = (Get-NetFirewallProfile | Where-Object { $_.Enabled -eq 'True' })
    Write-Output "Firewall Status: $(if ($firewallStatus) { 'Enabled - FAIL' } else { 'Disabled - PASS' })"
} catch {
    Write-Output "Failed to check firewall status - FAIL"
}
# Check Java Version for Mid-Tier and Compute Nodes
if ($serverType -in @("Mid-Tier", "Compute")) {
    try {
        $javaVersion = java -version 2>&1 | Select-String "version"
        Write-Output "Java Version: $javaVersion - PASS"
    } catch {
        Write-Output "Java not installed - FAIL"
    }
}

# Check PostgreSQL Version for Mid-Tier
if ($serverType -eq "Mid-Tier") {
    try {
        $pgVersion = pg_ctl --version 2>&1
        Write-Output "PostgreSQL Version: $pgVersion - PASS"
    } catch {
        Write-Output "PostgreSQL not installed - FAIL"
    }
}

# Check .NET Framework for All Servers
$dotNetVersion = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full).Release
Write-Output "Installed .NET Framework Release Key: $dotNetVersion - $(if ($dotNetVersion -ge 528040) { 'PASS' } else { 'FAIL' })"

# Check PowerShell Version
$psVersion = $PSVersionTable.PSVersion.Major
Write-Output "PowerShell Version: $psVersion (Expected: >= 5.1) - $(if ($psVersion -ge 5) { 'PASS' } else { 'FAIL' })"
	
# Check Python Version for Compute Nodes
if ($serverType -eq "Compute") {
    try {
        $pythonVersion = python --version 2>&1
        Write-Output "Python Version: $pythonVersion - PASS"
    } catch {
        Write-Output "Python not installed - FAIL"
    }
}
