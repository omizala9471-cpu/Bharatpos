# BharatPOS SRE Synthetic Monitor
# This script performs periodic synthetics to verify page loads, resource integrity, DOM element presence, and takes screenshots on failure.

$ProjectDir = "C:\Users\User\.gemini\antigravity\scratch\upi-whatsapp-invoice-generator"
$LogFile = "$ProjectDir\monitoring_log.json"
$ReportFile = "$ProjectDir\monitoring_report.md"

# Define target endpoints to test (checking localhost ports commonly used by dev servers, falling back to file paths)
$UrlsToTest = @(
    "http://localhost:3000/index.html",
    "http://localhost:8080/index.html"
)

# CDN dependencies to verify
$CdnsToTest = @(
    "https://unpkg.com/lucide@latest",
    "https://cdnjs.cloudflare.com/ajax/libs/qrious/4.0.2/qrious.min.js",
    "https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js",
    "https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js",
    "https://cdn.jsdelivr.net/npm/hash-wasm@4.11.0/dist/argon2.umd.min.js"
)

# Critical DOM IDs representing key workflows (Login, Checkout, Search)
$RequiredDomElements = @(
    "authForm",        # Login / Register workflow
    "addItemBtn",      # Checkout / Line item workflow
    "saveInvoiceBtn",  # Save Ledger workflow
    "paymentMode",     # Financial checkout settings
    "historyBody",     # Search / Ledger history
    "excelDropZone"    # Admin Panel Excel tools
)

$Results = [ordered]@{
    Timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    Status = "SUCCESS"
    LoadTimeMs = 0
    Errors = @()
}

# 1. Determine active host/URL
$TargetUrl = ""
foreach ($url in $UrlsToTest) {
    try {
        $resp = Invoke-WebRequest -Uri $url -Method Head -TimeoutSec 2 -UseBasicParsing -ErrorAction Stop
        if ($resp.StatusCode -eq 200) {
            $TargetUrl = $url
            break
        }
    } catch {}
}

# 2. Perform Web/Filesystem Load Check
$LoadStart = [DateTime]::UtcNow
if ($TargetUrl) {
    # Test network load time of the main page
    try {
        $pageResponse = Invoke-WebRequest -Uri $TargetUrl -Method Get -TimeoutSec 5 -UseBasicParsing
        $LoadEnd = [DateTime]::UtcNow
        $Results.LoadTimeMs = [Math]::Round(($LoadEnd - $LoadStart).TotalMilliseconds)
        
        if ($pageResponse.StatusCode -ge 400) {
            $Results.Status = "FAILURE"
            $Results.Errors += "HTTP error code: $($pageResponse.StatusCode) on $TargetUrl"
        }
    } catch {
        $Results.Status = "FAILURE"
        $Results.Errors += "Failed to request $TargetUrl : $($_.Exception.Message)"
    }
} else {
    # Fallback to Local Filesystem Integrity Check
    $indexPath = "$ProjectDir\index.html"
    if (Test-Path $indexPath) {
        $LoadEnd = [DateTime]::UtcNow
        $Results.LoadTimeMs = [Math]::Round(($LoadEnd - $LoadStart).TotalMilliseconds)
    } else {
        $Results.Status = "FAILURE"
        $Results.Errors += "index.html not found on path: $indexPath"
    }
}

# 3. Verify Local Resource Load Times (< 2 seconds check)
if ($Results.LoadTimeMs -gt 2000) {
    $Results.Status = "FAILURE"
    $Results.Errors += "Page load time exceeded 2 seconds limit: $($Results.LoadTimeMs)ms"
}

# 4. Verify CDNs are active & responsive (Uptime Check)
foreach ($cdn in $CdnsToTest) {
    $cdnStart = [DateTime]::UtcNow
    try {
        $cdnResp = Invoke-WebRequest -Uri $cdn -Method Head -TimeoutSec 3 -UseBasicParsing -ErrorAction Stop
        $cdnEnd = [DateTime]::UtcNow
        $cdnTime = ($cdnEnd - $cdnStart).TotalMilliseconds
        
        if ($cdnTime -gt 2000) {
            $Results.Errors += "Warning: CDN load slow ($($cdnTime)ms) for $cdn"
        }
    } catch {
        $Results.Status = "FAILURE"
        $Results.Errors += "Failed to reach CDN: $cdn ($($_.Exception.Message))"
    }
}

# 5. Verify DOM Integrity of Workflows (Login, Checkout, Search elements exist)
$indexPath = "$ProjectDir\index.html"
if (Test-Path $indexPath) {
    $htmlContent = Get-Content $indexPath -Raw
    foreach ($element in $RequiredDomElements) {
        if ($htmlContent -notmatch "id=['`"]$element['`"]") {
            $Results.Status = "FAILURE"
            $Results.Errors += "Missing critical DOM element required for workflow: id='$element'"
        }
    }
}

# 6. Failure Recovery: Capture Screenshot & Log Error Artifact
if ($Results.Status -eq "FAILURE") {
    # Take Desktop Screenshot using native .NET Forms API
    try {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        
        $Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
        $Width = $Screen.Width
        $Height = $Screen.Height
        $Left = $Screen.Left
        $Top = $Screen.Top
        
        $Bitmap = New-Object System.Drawing.Bitmap $Width, $Height
        $Graphic = [System.Drawing.Graphics]::FromImage($Bitmap)
        $Graphic.CopyFromScreen($Left, $Top, 0, 0, $Bitmap.Size)
        
        $ScreenshotName = "error_screenshot_$(Get-Date -Format 'yyyyMMdd_HHmmss').png"
        $ScreenshotPath = "$ProjectDir\$ScreenshotName"
        $Bitmap.Save($ScreenshotPath, [System.Drawing.Imaging.ImageFormat]::Png)
        
        $Graphic.Dispose()
        $Bitmap.Dispose()
        $Results.Errors += "Failure screenshot saved to: $ScreenshotName"
    } catch {
        $Results.Errors += "Failed to capture screenshot: $($_.Exception.Message)"
    }
    
    # Generate SRE Error Report Markdown Artifact
    $ReportMD = @"
# 🚨 Synthetic Monitoring Failure Report
* **Timestamp**: $($Results.Timestamp)
* **Status**: FAILURE
* **Load Time**: $($Results.LoadTimeMs)ms
* **Target Host**: $(if ($TargetUrl) { $TargetUrl } else { 'Local Filesystem' })

### Error Messages:
$( ($Results.Errors | ForEach-Object { "* [ERR] $_" }) -join "`n" )

### Recommended Actions:
1. Verify if the local dev server is running on port 3000 (`npm run dev`).
2. Check if the local project path is accessible.
3. Open browser console to check for any unhandled JavaScript script compilation crashes.
"@
    Set-Content -Path $ReportFile -Value $ReportMD
}

# 7. Write results to JSON Log (appending to history log)
$LogArray = @()
if (Test-Path $LogFile) {
    try {
        $LogArray = Get-Content $LogFile -Raw | ConvertFrom-Json
        if ($LogArray -isnot [array]) {
            $LogArray = @($LogArray)
        }
    } catch {}
}
$LogArray += $Results
# Keep only the last 100 entries to prevent log bloat
if ($LogArray.Count -gt 100) {
    $LogArray = $LogArray[-100..-1]
}
$LogArray | ConvertTo-Json -Depth 5 | Set-Content $LogFile
Write-Host "Monitoring execution completed. Status: $($Results.Status)"
