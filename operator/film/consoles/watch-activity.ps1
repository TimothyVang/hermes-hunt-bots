param([Parameter(Mandatory)][string]$LabUrl, [Parameter(Mandatory)][string]$Title)
# Every bot tool call as the lab VM itself records it (guest /activity), starting from now.
$Host.UI.RawUI.WindowTitle = $Title
[System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy

function Fit-Buffer {
  try { $r = $Host.UI.RawUI; $w = $r.WindowSize.Width
        if ($r.BufferSize.Width -ne $w) { $r.BufferSize = New-Object Management.Automation.Host.Size($w, 5000) } } catch {}
}

$names = @{ 'framework-coordinator' = 'IR Lead'; 'framework-researcher' = 'Threat Hunter'; 'framework-network-analyst' = 'Network Analyst';
            'framework-librarian' = 'Threat Intel'; 'framework-builder' = 'Detection Eng'; 'framework-reviewer' = 'Purple Team' }
$color = @{ 'framework-researcher' = 'Cyan'; 'framework-network-analyst' = 'Yellow'; 'framework-librarian' = 'Magenta'; 'framework-builder' = 'Green'; 'framework-reviewer' = 'Red' }
$after = 0
do { $page = Invoke-RestMethod "$LabUrl/activity?after=$after&limit=100"; $after = $page.next } while ($page.more)
Write-Host "Lab VM activity feed - case $($page.case_id) - new tool calls appear below" -ForegroundColor DarkGray
while ($true) {
  Fit-Buffer
  try { $page = Invoke-RestMethod "$LabUrl/activity?after=$after&limit=100" } catch { Start-Sleep 2; continue }
  foreach ($e in @($page.entries)) {
    $p = $e.params; $arg = @()
    foreach ($k in 'q', 'expression', 'field', 'dataset', 'host') { if ($p.$k) { $arg += "$k=$($p.$k)" } }
    $res = if ($e.error) { "ERROR $($e.error)" } else { "$($e.result_count) results of $($e.total)" }
    $t = ([datetime]$e.time).ToLocalTime().ToString('HH:mm:ss')
    $c = if ($color[$e.profile]) { $color[$e.profile] } else { 'White' }
    Write-Host ("{0} {1,-15} {2,-17} {3} -> {4}" -f $t, $names[$e.profile], $e.tool, ($arg -join ' '), $res) -ForegroundColor $c
  }
  $after = $page.next
  Start-Sleep -Milliseconds 700
}
