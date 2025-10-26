Write-Host "=== Checking for File Explorer Triggers ===" -ForegroundColor Cyan

# --- Autorun entries that mention explorer.exe ---
$regPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
)

$found = @()

foreach ($path in $regPaths) {
    if (Test-Path $path) {
        Get-ItemProperty $path | ForEach-Object {
            $_.PSObject.Properties |
            Where-Object { $_.Value -match "explorer.exe" -and $_.Name -notmatch "PS" } |
            ForEach-Object {
                $found += [PSCustomObject]@{
                    Source  = "Registry Run"
                    KeyPath = $path
                    Name    = $_.Name
                    Command = $_.Value
                }
            }
        }
    }
}

# --- Startup folders ---
$startupFolders = @(
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:AppData\Microsoft\Windows\Start Menu\Programs\Startup"
)
foreach ($folder in $startupFolders) {
    if (Test-Path $folder) {
        Get-ChildItem $folder -Recurse -ErrorAction SilentlyContinue | 
        Where-Object { $_.FullName -match "explorer.exe" } | 
        ForEach-Object {
            $found += [PSCustomObject]@{
                Source  = "Startup Folder"
                KeyPath = $folder
                Name    = $_.Name
                Command = $_.FullName
            }
        }
    }
}

# --- Scheduled Tasks launching explorer.exe ---
Get-ScheduledTask | ForEach-Object {
    $_.Actions | Where-Object { $_.Execute -match "explorer.exe" } | ForEach-Object {
        $found += [PSCustomObject]@{
            Source  = "Scheduled Task"
            KeyPath = $_.Execute
            Name    = $_.TaskName
            Command = "$($_.Execute) $($_.Arguments)"
        }
    }
}

# --- Running processes that have spawned explorer.exe ---
$explorerParents = Get-CimInstance Win32_Process | Where-Object { $_.Name -eq "explorer.exe" }
foreach ($proc in $explorerParents) {
    try {
        $parent = Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.ParentProcessId)"
        if ($parent.Name -and $parent.Name -ne "System" -and $parent.Name -ne "explorer.exe") {
            $found += [PSCustomObject]@{
                Source  = "Active Process"
                KeyPath = "PID $($parent.ProcessId)"
                Name    = $parent.Name
                Command = $parent.CommandLine
            }
        }
    } catch {}
}

if ($found.Count -eq 0) {
    Write-Host "No autoruns or processes found that directly launch File Explorer." -ForegroundColor Yellow
} else {
    Write-Host "`n=== Potential Triggers Found ===" -ForegroundColor Green
    $i = 1
    $found | ForEach-Object {
        Write-Host "`n[$i]" -ForegroundColor Cyan
        Write-Host "Source:  $($_.Source)"
        Write-Host "Name:    $($_.Name)"
        Write-Host "Command: $($_.Command)"
        Write-Host "KeyPath: $($_.KeyPath)"
        $i++
    }
}
