<#
    Captures the workbench, one PNG per section, for the README and the release page.

    Screen capture rather than PrintWindow: the workbench content is drawn by WebView2
    in its own process with its own composition surface, and PrintWindow returns that
    region blank. Copying from the screen device context is what actually produces the
    pixels a person would see.

    That means the window has to be visible and in front, so this steals focus for a few
    seconds per shot. It is a build-time tool, not something the app does.

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
    [string]$Views = 'overview,findings,tree,network,capture,assistant,remediate,fleet',
    [int]$Width = 1500,
    [int]$Height = 940
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = Resolve-Path (Join-Path $here '..\..')

if ([string]::IsNullOrEmpty($Output)) { $Output = Join-Path $repo 'docs\images' }
New-Item -ItemType Directory -Force -Path $Output | Out-Null
$Output = (Resolve-Path $Output).Path

$exe = Join-Path $repo 'src\CaYaTrace.App\bin\x64\Debug\net8.0-windows\win-x64\CaYaTrace.exe'
if (-not (Test-Path $exe)) {
    $exe = (Get-ChildItem -Recurse -Filter CaYaTrace.exe (Join-Path $repo 'src\CaYaTrace.App\bin') |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
}
if (-not (Test-Path $exe)) { throw "CaYaTrace.exe not found. Build the solution first." }

Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms

Add-Type @'
using System;
using System.Runtime.InteropServices;

public static class Win {
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
    [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr h, int x, int y, int w, int t, bool repaint);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left, Top, Right, Bottom; }

    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);

    // The window rectangle includes the invisible resize border DWM keeps around a
    // window; cropping to the extended frame bounds is what removes the transparent
    // margin from the saved image.
    [DllImport("dwmapi.dll")]
    public static extern int DwmGetWindowAttribute(IntPtr h, int attr, out RECT r, int size);
    public const int DWMWA_EXTENDED_FRAME_BOUNDS = 9;
}
'@

[void][Win]::SetProcessDPIAware()

function Capture-Window {
    param([IntPtr]$Handle, [string]$Path)

    $rect = New-Object Win+RECT
    $ok = [Win]::DwmGetWindowAttribute($Handle, [Win]::DWMWA_EXTENDED_FRAME_BOUNDS,
        [ref]$rect, [System.Runtime.InteropServices.Marshal]::SizeOf($rect))

    if ($ok -ne 0) { [void][Win]::GetWindowRect($Handle, [ref]$rect) }

    $w = $rect.Right - $rect.Left
    $h = $rect.Bottom - $rect.Top
    if ($w -le 0 -or $h -le 0) { throw "window has no size" }

    $bmp = New-Object System.Drawing.Bitmap($w, $h, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($rect.Left, $rect.Top, 0, 0, (New-Object System.Drawing.Size($w, $h)))
    $g.Dispose()

    # Encoded to memory and written with File I/O rather than Bitmap.Save(path).
    # GDI+ resolves a relative path against the process working directory, not the
    # shell's, and reports every failure as the same opaque "generic error".
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    [System.IO.File]::WriteAllBytes($Path, $ms.ToArray())
    $ms.Dispose()
    $bmp.Dispose()
}

$viewList = $Views.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }

foreach ($view in $viewList) {
    # $($view) rather than $view: PowerShell takes the following character as part of
    # the variable name, and the resulting "$viewX" is undefined.
    Write-Host "capturing $($view)..."

    $args = @('--session', $Session, '--view', $view, '--lang', $Language)
    $process = Start-Process -FilePath $exe -ArgumentList $args -PassThru

    $handle = [IntPtr]::Zero
    for ($i = 0; $i -lt 100; $i++) {
        Start-Sleep -Milliseconds 250
        $process.Refresh()
        if ($process.MainWindowHandle -ne [IntPtr]::Zero -and [Win]::IsWindowVisible($process.MainWindowHandle)) {
            $handle = $process.MainWindowHandle
            break
        }
    }

    if ($handle -eq [IntPtr]::Zero) {
        Write-Warning "no window for $view"
        try { $process.Kill() } catch { }
        continue
    }

    [void][Win]::MoveWindow($handle, 60, 40, $Width, $Height, $true)
    [void][Win]::ShowWindow($handle, 5)
    [void][Win]::SetForegroundWindow($handle)

    # The session projection and the first paint both happen after the window appears.
    # Capturing too early produces a picture of an empty shell.
    Start-Sleep -Seconds 4

    $path = Join-Path $Output ("workbench-$view" + $(if ($Language -ne 'en') { "-$Language" } else { '' }) + '.png')
    Capture-Window -Handle $handle -Path $path
    Write-Host "  $path"

    try { $process.CloseMainWindow() | Out-Null; Start-Sleep -Milliseconds 800 } catch { }
    try { if (-not $process.HasExited) { $process.Kill() } } catch { }
}

Write-Host ""
Write-Host "done: $Output"
