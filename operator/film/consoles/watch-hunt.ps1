param([Parameter(Mandatory)][string]$Workflow, [Parameter(Mandatory)][string]$Python, [Parameter(Mandatory)][string]$Framework,
      [Parameter(Mandatory)][string]$Title, [string]$Address = '', [string]$Queue = '')
# Live hunt progress from the Temporal workflow itself: each finished stage, its bot and claim count.
$Host.UI.RawUI.WindowTitle = $Title
. "$PSScriptRoot\font.ps1"
Set-ConsoleFont 20
$names = @{ 'framework-coordinator' = 'IR Lead'; 'framework-researcher' = 'Threat Hunter'; 'framework-network-analyst' = 'Network Analyst';
            'framework-librarian' = 'Threat Intel'; 'framework-builder' = 'Detection Eng'; 'framework-reviewer' = 'Purple Team' }
$steps = 'scope', 'evidence', 'hypotheses', 'network', 'intel', 'analysis', 'detection', 'purple', 'incident'
$cli = @('-B', '-m', 'hermes_temporal.cli')
if ($Address) { $cli += '--address', $Address }
if ($Queue) { $cli += '--task-queue', $Queue }
$done = @{}; $last = ''
Push-Location $Framework
Write-Host 'Hunt stage progress' -ForegroundColor DarkGray

function Fit-Buffer {
  try { $r = $Host.UI.RawUI; $w = $r.WindowSize.Width
        if ($r.BufferSize.Width -ne $w) { $r.BufferSize = New-Object Management.Automation.Host.Size($w, 5000) } } catch {}
}
while ($true) {
  Fit-Buffer
  $p = (& $Python @cli practice-status $Workflow 2>$null) | ConvertFrom-Json -ErrorAction SilentlyContinue
  if ($p) {
    $line = "round $($p.round_index)/$($p.rounds) $($p.stage) $($p.temporal_status)"
    if ($line -ne $last) { Write-Host ("{0} {1}" -f (Get-Date -Format HH:mm:ss), $line) -ForegroundColor Green; $last = $line }
    if ($p.child_workflow_id) {
      $c = (& $Python @cli status $p.child_workflow_id 2>$null) | ConvertFrom-Json -ErrorAction SilentlyContinue
      $results = @($c.results)
      for ($i = 0; $i -lt $results.Count; $i++) {
        $r = $results[$i]
        if ($done[$r.execution_id]) { continue }
        $done[$r.execution_id] = $true
        try { $o = $r.output | ConvertFrom-Json } catch { $o = $null }
        if ($o) {
          $bot = if ($names[$o.profile]) { $names[$o.profile] } else { $o.profile }
          Write-Host ("{0} {1,-10} {2} {3} claims" -f (Get-Date -Format HH:mm:ss), $o.step_id, $bot, @($o.claims).Count) -ForegroundColor White
        } else {
          Write-Host ("{0} {1,-10} {2}" -f (Get-Date -Format HH:mm:ss), $steps[$i], $r.status) -ForegroundColor DarkYellow
        }
      }
    }
  }
  Start-Sleep -Seconds 5
}
