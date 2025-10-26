Write-Host "=== Autorun Entries and Tasks ===" -ForegroundColor Cyan

$autoruns = @()
$regPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
)

foreach ($path in $regPaths) {
    if (Test-Path $path) {
        Get-ItemProperty $path | ForEach-Object {
            $_.PSObject.Properties | Where-Object { $_.Name -notmatch "PSPath|PSParentPath|PSChildName|PSDrive|PSProvider" } | ForEach-Object {
                $autoruns += [PSCustomObject]@{
                    Source = $path
                    Name   = $_.Name
                    Command = $_.Value
                    Type = "Registry Run"
                }
            }
        }
    }
}

$tasks = Get-ScheduledTask | Where-Object { $_.Actions.Execute -match ".exe|.bat|.cmd|.vbs|.ps1" } | ForEach-Object {
    [PSCustomObject]@{
        Source = $_.TaskName
        Name   = $_.Actions.Execute
        Command = $_.Actions.Arguments
        Type = "Scheduled Task"
    }
}

$autoruns += $tasks

if ($autoruns.Count -eq 0) {
    Write-Host "No autorun entries or executable tasks found." -ForegroundColor Yellow
    exit
}

$index = 1
$autoruns | ForEach-Object {
    Write-Host "`n[$index]" -ForegroundColor Green
    Write-Host "Type:    $($_.Type)"
    Write-Host "Name:    $($_.Name)"
    Write-Host "Command: $($_.Command)"
    Write-Host "Source:  $($_.Source)"
    $index++
}

$choice = Read-Host "`nEnter the numbers (comma-separated) of entries to attempt to kill their processes, or press Enter to skip"
if (![string]::IsNullOrWhiteSpace($choice)) {
    $nums = $choice -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' }
    foreach ($num in $nums) {
        $entry = $autoruns[$num - 1]
        if ($entry) {
            Write-Host "Attempting to find and kill processes matching: $($entry.Name)" -ForegroundColor Yellow
            $procName = [System.IO.Path]::GetFileNameWithoutExtension(($entry.Name -split '\\')[-1])
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

Write-Host "`nDone. Review entries carefully — disabling or deleting autoruns should be done manually if you’re unsure." -ForegroundColor Cyan
