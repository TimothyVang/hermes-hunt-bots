param([Parameter(Mandatory)][string]$LabUrl, [Parameter(Mandatory)][string]$Title)
# Every bot tool call as the lab VM itself records it (guest /activity), starting from now.
$Host.UI.RawUI.WindowTitle = $Title
. "$PSScriptRoot\font.ps1"
Set-ConsoleFont 22
[System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy

function Fit-Buffer {
  try { $r = $Host.UI.RawUI; $w = $r.WindowSize.Width
        if ($r.BufferSize.Width -ne $w) { $r.BufferSize = New-Object Management.Automation.Host.Size($w, 5000) } } catch {}
}

$names = @{ 'framework-coordinator' = 'IR Lead'; 'framework-researcher' = 'Hunter'; 'framework-network-analyst' = 'Analyst';
            'framework-librarian' = 'Intel'; 'framework-builder' = 'Detection'; 'framework-reviewer' = 'Purple' }
$color = @{ 'framework-researcher' = 'Cyan'; 'framework-network-analyst' = 'Yellow'; 'framework-librarian' = 'Magenta'; 'framework-builder' = 'Green'; 'framework-reviewer' = 'Red' }
$after = 0
do { $page = Invoke-RestMethod "$LabUrl/activity?after=$after&limit=100"; $after = $page.next } while ($page.more)
Write-Host "Lab activity - case $($page.case_id) - every bot tool call" -ForegroundColor DarkGray
while ($true) {
  Fit-Buffer
  try { $page = Invoke-RestMethod "$LabUrl/activity?after=$after&limit=100" } catch { Start-Sleep 2; continue }
  foreach ($e in @($page.entries)) {
    $p = $e.params; $arg = @()
    foreach ($k in 'q', 'expression', 'field', 'dataset', 'host') { if ($p.$k) { $arg += $(if ($k -in 'q', 'expression') { $p.$k } else { "$k=$($p.$k)" }) } }
    $res = if ($e.error) { "ERROR $($e.error)" } elseif ($null -ne $e.total) { "$($e.result_count)/$($e.total)" } else { "$($e.result_count)" }
    $t = ([datetime]$e.time).ToLocalTime().ToString('HH:mm:ss')
    $c = if ($color[$e.profile]) { $color[$e.profile] } else { 'White' }
    Write-Host ("{0} {1,-9} {2,-17} {3} -> {4}" -f $t, $names[$e.profile], $e.tool, ($arg -join ' '), $res) -ForegroundColor $c
  }
  $after = $page.next
  Start-Sleep -Milliseconds 700
}
