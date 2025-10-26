Write-Host "=== Non-Windows Autorun Entries and Tasks ===" -ForegroundColor Cyan

$autoruns = @()
$regPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
)

foreach ($path in $regPaths) {
    if (Test-Path $path) {
        Get-ItemProperty $path | ForEach-Object {
            $_.PSObject.Properties | Where-Object { $_.Name -notmatch "PSPath|PSParentPath|PSChildName|PSDrive|PSProvider" } | ForEach-Object {
                $exe = ($_.Value -split '\s+')[0]
                if ($exe -and (Test-Path $exe)) {
                    $file = Get-Item $exe -ErrorAction SilentlyContinue
                    $sig = Get-AuthenticodeSignature $exe -ErrorAction SilentlyContinue
                    if ($sig.SignerCertificate.Subject -notmatch "Microsoft" -and $sig.SignerCertificate.Subject -notmatch "Windows") {
                        $info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($exe)
                        $autoruns += [PSCustomObject]@{
                            Type = "Registry Run"
                            Name = $_.Name
                            Command = $_.Value
                            Description = if ($info.FileDescription) { $info.FileDescription } else { "N/A" }
                            Publisher = if ($info.CompanyName) { $info.CompanyName } else { "Unknown" }
                            Path = $exe
                        }
                    }
                }
            }
        }
    }
}

$tasks = Get-ScheduledTask | Where-Object { $_.Actions.Execute -match ".exe|.bat|.cmd|.vbs|.ps1" } | ForEach-Object {
    $exe = $_.Actions.Execute
    if (Test-Path $exe) {
        $sig = Get-AuthenticodeSignature $exe -ErrorAction SilentlyContinue
        if ($sig.SignerCertificate.Subject -notmatch "Microsoft" -and $sig.SignerCertificate.Subject -notmatch "Windows") {
            $info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($exe)
            [PSCustomObject]@{
                Type = "Scheduled Task"
                Name = $_.TaskName
                Command = "$exe $($_.Actions.Arguments)"
                Description = if ($info.FileDescription) { $info.FileDescription } else { "N/A" }
                Publisher = if ($info.CompanyName) { $info.CompanyName } else { "Unknown" }
                Path = $exe
            }
        }
    }
}

$autoruns += $tasks
if ($autoruns.Count -eq 0) {
    Write-Host "No non-Windows autorun entries or executable tasks found." -ForegroundColor Yellow
    exit
}

$index = 1
$autoruns | ForEach-Object {
    Write-Host "`n[$index]" -ForegroundColor Green
    Write-Host "Type:        $($_.Type)"
    Write-Host "Name:        $($_.Name)"
    Write-Host "Publisher:   $($_.Publisher)"
    Write-Host "Description: $($_.Description)"
    Write-Host "Command:     $($_.Command)"
    Write-Host "Path:        $($_.Path)"
    $index++
}

$choice = Read-Host "`nEnter numbers (comma-separated) of entries to attempt to kill their processes, or press Enter to skip"
if (![string]::IsNullOrWhiteSpace($choice)) {
    $nums = $choice -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' }
    foreach ($num in $nums) {
        $entry = $autoruns[$num - 1]
        if ($entry) {
            Write-Host "Attempting to find and kill process: $($entry.Name)" -ForegroundColor Yellow
            $procName = [System.IO.Path]::GetFileNameWithoutExtension(($entry.Path -split '\\')[-1])
            $procs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $procName }
            if ($procs) {
                $procs | Stop-Process -Force -ErrorAction SilentlyContinue
                Write-Host "Stopped process: $procName" -ForegroundColor Green
            } else {
                Write-Host "No matching process found for: $procName" -ForegroundColor DarkYellow
            }
        }
    }
}

Write-Host "`nDone. Only non-Microsoft autoruns were listed." -ForegroundColor Cyan
