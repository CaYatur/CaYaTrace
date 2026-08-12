<#
    Renders the workbench, one PNG per section, for the README and the release page.

    Capture goes through the workbench's own --screenshot option, which uses WebView2's
    preview API. An earlier version copied from the screen device context; that requires
    the window to be visible and in front, and on a machine somebody is actually using,
    SetForegroundWindow does not always win. The result was an image of the operator's
    browser instead of the tool. A documentation build must not be able to photograph
    anything but the page it is documenting.

    The window is positioned off-screen and never takes focus, so this can run while the
    machine is in use.

    Usage:
      powershell -ExecutionPolicy Bypass -File tools/screenshots/capture.ps1 `
          -Session <session dir> [-Output docs/images] [-Language en]
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Session,
    [string]$Output = '',
    [string]$Language = 'en',

    # A comma-separated string rather than a string array: invoked through
    # `powershell -File`, every argument arrives as a separate token and an array
    # parameter swallows only the first, binding the rest to whatever comes next.
    [string]$Views = 'overview,findings,tree,network,capture,sessions,compare,assistant,remediate,fleet',
    [int]$TimeoutSeconds = 90
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = Resolve-Path (Join-Path $here '..\..')

if ([string]::IsNullOrEmpty($Output)) { $Output = Join-Path $repo 'docs\images' }
New-Item -ItemType Directory -Force -Path $Output | Out-Null
$Output = (Resolve-Path $Output).Path

$exe = Join-Path $repo 'artifacts\win-x64\CaYaTrace.exe'
if (-not (Test-Path $exe)) {
    $exe = Join-Path $repo 'src\CaYaTrace.App\bin\x64\Debug\net8.0-windows\win-x64\CaYaTrace.exe'
}
if (-not (Test-Path $exe)) {
    $exe = (Get-ChildItem -Recurse -Filter CaYaTrace.exe (Join-Path $repo 'src\CaYaTrace.App\bin') |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
}
if (-not (Test-Path $exe)) { throw "CaYaTrace.exe not found. Build or publish first." }

Write-Host "using $exe"

$viewList = $Views.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
$suffix = ''
if ($Language -ne 'en') { $suffix = "-$Language" }

foreach ($view in $viewList) {
    $path = Join-Path $Output ("workbench-$view" + $suffix + '.png')
    Write-Host "rendering $($view)..."

    $args = @('--session', $Session, '--view', $view, '--lang', $Language, '--screenshot', $path)
    $process = Start-Process -FilePath $exe -ArgumentList $args -PassThru -WindowStyle Hidden

    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        try { $process.Kill() } catch { }
        Write-Warning "timed out on $view"
        continue
    }

    if (Test-Path $path) {
        $size = (Get-Item $path).Length
        Write-Host "  $path ($size bytes)"
    }
    else {
        Write-Warning "no image produced for $view"
    }
}

Write-Host ""
Write-Host "done: $Output"
