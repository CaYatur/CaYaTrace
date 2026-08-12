<#
    Draws the CaYaTrace application icon and packs it into a multi-resolution .ico.

    The icon is generated rather than hand-drawn so it stays in step with the mark used
    in the workbench header: both come from the same geometry, expressed once here.

    Two things this script does that a straight export would not:

      * It simplifies at small sizes. The full mark — two rings, a core, three satellite
        nodes and the lines between them — is legible at 64px and above. At 32px the
        connecting lines land on sub-pixel widths and turn to grey mud, so they are
        dropped; at 16px only the outer ring and the core survive. An icon that is
        "correct" but unreadable in the taskbar is not correct.

      * It supersamples. Each size is drawn at four times the resolution and downsampled
        bicubically, because GDI+ antialiasing of a 1px stroke at 16px is visibly worse
        than a downsampled 4px stroke at 64px.

    Sizes 16-48 are stored as 32-bit BMP with an AND mask, 64 and up as PNG. Windows 10
    and 11 read PNG at every size, but the BMP entries cost little and keep the file
    correct for anything that reads the icon through an older path.

    Usage:  powershell -ExecutionPolicy Bypass -File tools/icon/make-icon.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = '',
    [string]$PreviewPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Resolved here rather than in the param block: $PSScriptRoot is not reliably bound
# while parameter defaults are evaluated.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrEmpty($OutputPath)) {
    $OutputPath = Join-Path $here '..\..\src\CaYaTrace.App\Assets\cayatrace.ico'
}
if ([string]::IsNullOrEmpty($PreviewPath)) {
    $PreviewPath = Join-Path $here 'preview.png'
}

Add-Type -AssemblyName System.Drawing

# Brand tokens, matching src/CaYaTrace.App/Assets/theme.css.
$Primary   = [System.Drawing.Color]::FromArgb(255, 0xDC, 0x26, 0x26)
$PrimaryLt = [System.Drawing.Color]::FromArgb(255, 0xEF, 0x44, 0x44)
$BgDark    = [System.Drawing.Color]::FromArgb(255, 0x11, 0x18, 0x26)
$BgLift    = [System.Drawing.Color]::FromArgb(255, 0x1D, 0x2A, 0x40)
$TextPri   = [System.Drawing.Color]::FromArgb(255, 0xF8, 0xFA, 0xFC)
$Muted     = [System.Drawing.Color]::FromArgb(255, 0x94, 0xA3, 0xB8)

function New-RoundedPath {
    param([single]$X, [single]$Y, [single]$W, [single]$H, [single]$R)

    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = $R * 2
    $path.AddArc($X, $Y, $d, $d, 180, 90)
    $path.AddArc($X + $W - $d, $Y, $d, $d, 270, 90)
    $path.AddArc($X + $W - $d, $Y + $H - $d, $d, $d, 0, 90)
    $path.AddArc($X, $Y + $H - $d, $d, $d, 90, 90)
    $path.CloseFigure()
    return $path
}

<#
    Renders the mark at one size.

    All geometry is expressed in the 32-unit space of the workbench SVG and scaled
    here, so the icon and the header mark cannot drift apart.
#>
function New-IconBitmap {
    param([int]$Size)

    $ss = 4
    $big = $Size * $ss

    $bmp = New-Object System.Drawing.Bitmap($big, $big, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.Clear([System.Drawing.Color]::Transparent)

    # --- plate -------------------------------------------------------------
    # A filled plate rather than a floating mark: on a taskbar the icon sits on an
    # unknown background, and a red ring alone disappears against a dark one.
    $inset = [single]($big * 0.02)
    $plateW = [single]($big - 2 * $inset)
    $radius = [single]($big * 0.215)
    $plate = New-RoundedPath -X $inset -Y $inset -W $plateW -H $plateW -R $radius

    $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
        (New-Object System.Drawing.PointF(0, 0)),
        (New-Object System.Drawing.PointF([single]$big, [single]$big)),
        $BgLift, $BgDark)
    $g.FillPath($brush, $plate)
    $brush.Dispose()

    # Hairline rim so the plate keeps an edge against a dark taskbar.
    $rimWidth = [Math]::Max(1.0, $big * 0.014)
    $rimPen = New-Object System.Drawing.Pen(
        [System.Drawing.Color]::FromArgb(120, $Primary.R, $Primary.G, $Primary.B), [single]$rimWidth)
    $g.DrawPath($rimPen, $plate)
    $rimPen.Dispose()
    $plate.Dispose()

    # --- mark --------------------------------------------------------------
    # The 32-unit design space, centred and scaled to leave the plate a margin.
    $span = $big * 0.80
    $u = $span / 32.0
    $ox = ($big - $span) / 2.0
    $oy = ($big - $span) / 2.0

    $cx = $ox + 16 * $u
    $cy = $oy + 16 * $u

    function Circle { param([single]$X, [single]$Y, [single]$R)
        return New-Object System.Drawing.RectangleF(($X - $R), ($Y - $R), ($R * 2), ($R * 2)) }

    # Detail tiers. Below 32px the satellites and inner ring collapse into noise,
    # so the icon keeps only what still reads: the ring and the core.
    $full = $Size -ge 64
    $mid  = $Size -ge 32

    if ($mid) {
        $innerPen = New-Object System.Drawing.Pen(
            [System.Drawing.Color]::FromArgb(150, $Primary.R, $Primary.G, $Primary.B), [single](1.4 * $u))
        $g.DrawEllipse($innerPen, (Circle -X $cx -Y $cy -R (8 * $u)))
        $innerPen.Dispose()
    }

    if ($full) {
        $linePen = New-Object System.Drawing.Pen(
            [System.Drawing.Color]::FromArgb(205, $Muted.R, $Muted.G, $Muted.B), [single](1.25 * $u))
        $linePen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
        $linePen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
        $g.DrawLine($linePen, [single]($ox + 16 * $u), [single]($oy + 5.0 * $u), [single]($ox + 16 * $u), [single]($oy + 13 * $u))
        $g.DrawLine($linePen, [single]($ox + 17.9 * $u), [single]($oy + 17.3 * $u), [single]($ox + 25.6 * $u), [single]($oy + 21.6 * $u))
        $g.DrawLine($linePen, [single]($ox + 14.1 * $u), [single]($oy + 17.3 * $u), [single]($ox + 6.4 * $u), [single]($oy + 21.6 * $u))
        $linePen.Dispose()
    }

    # Outer ring last of the rings so the lines tuck under it.
    $outerPen = New-Object System.Drawing.Pen($Primary, [single](2.3 * $u))
    $g.DrawEllipse($outerPen, (Circle -X $cx -Y $cy -R (13.4 * $u)))
    $outerPen.Dispose()

    if ($mid) {
        $nodeBrush = New-Object System.Drawing.SolidBrush($TextPri)
        $g.FillEllipse($nodeBrush, (Circle -X ($ox + 16 * $u)   -Y ($oy + 2.6 * $u)  -R (2.5 * $u)))
        $g.FillEllipse($nodeBrush, (Circle -X ($ox + 27.2 * $u) -Y ($oy + 22.6 * $u) -R (2.5 * $u)))
        $g.FillEllipse($nodeBrush, (Circle -X ($ox + 4.8 * $u)  -Y ($oy + 22.6 * $u) -R (2.5 * $u)))
        $nodeBrush.Dispose()
    }

    $coreBrush = New-Object System.Drawing.SolidBrush($PrimaryLt)
    $coreRadius = 3.4
    if (-not $mid) { $coreRadius = 4.4 }
    $g.FillEllipse($coreBrush, (Circle -X $cx -Y $cy -R ($coreRadius * $u)))
    $coreBrush.Dispose()

    $g.Dispose()

    # Downsample. A 4x stroke reduced bicubically is markedly cleaner than the same
    # stroke drawn directly at the target size.
    $final = New-Object System.Drawing.Bitmap($Size, $Size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $fg = [System.Drawing.Graphics]::FromImage($final)
    $fg.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $fg.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $fg.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
    $fg.Clear([System.Drawing.Color]::Transparent)
    $fg.DrawImage($bmp, (New-Object System.Drawing.Rectangle(0, 0, $Size, $Size)))
    $fg.Dispose()
    $bmp.Dispose()

    return $final
}

function Get-PngBytes {
    param([System.Drawing.Bitmap]$Bitmap)

    $ms = New-Object System.IO.MemoryStream
    $Bitmap.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $bytes = $ms.ToArray()
    $ms.Dispose()
    return , $bytes
}

<#
    Packs a bitmap as an icon DIB: BITMAPINFOHEADER, then the colour rows bottom-up,
    then the 1bpp AND mask.

    biHeight is doubled — the header describes the XOR and AND planes together. The
    mask itself is left clear because the alpha channel already carries transparency;
    it exists because the format requires it, not because anything reads it.
#>
function Get-DibBytes {
    param([System.Drawing.Bitmap]$Bitmap)

    $w = $Bitmap.Width
    $h = $Bitmap.Height

    $ms = New-Object System.IO.MemoryStream
    $bw = New-Object System.IO.BinaryWriter($ms)

    $maskStride = [int]([Math]::Floor(($w + 31) / 32) * 4)

    $bw.Write([uint32]40)          # biSize
    $bw.Write([int32]$w)           # biWidth
    $bw.Write([int32]($h * 2))     # biHeight — XOR plane plus AND plane
    $bw.Write([uint16]1)           # biPlanes
    $bw.Write([uint16]32)          # biBitCount
    $bw.Write([uint32]0)           # biCompression = BI_RGB
    $bw.Write([uint32]($w * $h * 4 + $maskStride * $h))
    $bw.Write([int32]0); $bw.Write([int32]0)
    $bw.Write([uint32]0); $bw.Write([uint32]0)

    $rect = New-Object System.Drawing.Rectangle(0, 0, $w, $h)
    $data = $Bitmap.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::ReadOnly,
        [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    try {
        $row = New-Object byte[] ($w * 4)
        for ($y = $h - 1; $y -ge 0; $y--) {
            $scan = [System.IntPtr]::Add($data.Scan0, $y * $data.Stride)
            [System.Runtime.InteropServices.Marshal]::Copy($scan, $row, 0, $row.Length)
            $bw.Write($row)
        }
    }
    finally {
        $Bitmap.UnlockBits($data)
    }

    $maskRow = New-Object byte[] $maskStride
    for ($y = 0; $y -lt $h; $y++) { $bw.Write($maskRow) }

    $bw.Flush()
    $bytes = $ms.ToArray()
    $bw.Dispose()
    $ms.Dispose()
    return , $bytes
}

$sizes = @(16, 20, 24, 32, 40, 48, 64, 128, 256)
$images = @()

foreach ($size in $sizes) {
    $bitmap = New-IconBitmap -Size $size
    # PNG above 48: the payload is smaller and every Windows version this tool runs on
    # reads it. BMP below, where the saving is negligible and compatibility is free.
    if ($size -ge 64) { $payload = Get-PngBytes -Bitmap $bitmap; $isPng = $true }
    else { $payload = Get-DibBytes -Bitmap $bitmap; $isPng = $false }

    $images += [pscustomobject]@{ Size = $size; Bytes = $payload; IsPng = $isPng; Bitmap = $bitmap }
}

$out = New-Object System.IO.MemoryStream
$w = New-Object System.IO.BinaryWriter($out)

$w.Write([uint16]0)                  # reserved
$w.Write([uint16]1)                  # type 1 = icon
$w.Write([uint16]$images.Count)

$offset = 6 + 16 * $images.Count
foreach ($image in $images) {
    # 256 is written as 0: the field is one byte and 256 does not fit.
    $dim = $image.Size
    if ($dim -ge 256) { $dim = 0 }

    $w.Write([byte]$dim)
    $w.Write([byte]$dim)
    $w.Write([byte]0)                # palette entries — none, this is 32bpp
    $w.Write([byte]0)                # reserved
    $w.Write([uint16]1)              # colour planes
    $w.Write([uint16]32)             # bits per pixel
    $w.Write([uint32]$image.Bytes.Length)
    $w.Write([uint32]$offset)
    $offset += $image.Bytes.Length
}

foreach ($image in $images) { $w.Write($image.Bytes) }
$w.Flush()

$resolved = [System.IO.Path]::GetFullPath($OutputPath)
[System.IO.File]::WriteAllBytes($resolved, $out.ToArray())
$w.Dispose()
$out.Dispose()

# A contact sheet, so a change to the geometry can be judged at every size at once
# instead of by opening the .ico in something that only shows the largest entry.
$sheetPad = 12
$sheetW = ($images | ForEach-Object { $_.Size + $sheetPad } | Measure-Object -Sum).Sum + $sheetPad
$sheet = New-Object System.Drawing.Bitmap([int]$sheetW, 300, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
$sg = [System.Drawing.Graphics]::FromImage($sheet)
$sg.Clear([System.Drawing.Color]::FromArgb(255, 0x0B, 0x10, 0x1B))
$x = $sheetPad
foreach ($image in $images) {
    $sg.DrawImage($image.Bitmap, $x, [int](270 - $image.Size))
    $x += $image.Size + $sheetPad
}
$sg.Dispose()
$sheet.Save([System.IO.Path]::GetFullPath($PreviewPath), [System.Drawing.Imaging.ImageFormat]::Png)
$sheet.Dispose()

foreach ($image in $images) { $image.Bitmap.Dispose() }

Write-Host "icon     $resolved"
Write-Host "sizes    $($sizes -join ', ')"
Write-Host "bytes    $((Get-Item $resolved).Length)"
Write-Host "preview  $([System.IO.Path]::GetFullPath($PreviewPath))"
