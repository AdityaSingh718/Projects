# Quick APK Build Script for Posture Detection App
# Builds the debug APK with YOLOv11 integration

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   Posture Detection App - APK Builder" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Get script directory
$ProjectRoot = "c:\Users\prash\OneDrive\Desktop\Semester 3\ESW 2\ESWposedetection"
Set-Location $ProjectRoot

# Check if ONNX model exists
$OnnxPath = "app\src\main\assets\yolo11n-pose.onnx"
if (-not (Test-Path $OnnxPath)) {
    Write-Host "ERROR: ONNX model not found!" -ForegroundColor Red
    Write-Host "Expected: $OnnxPath" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Copying model from Model folder..." -ForegroundColor Yellow
    
    $SourcePath = "Model\yolo11n-pose.onnx"
    if (Test-Path $SourcePath) {
        Copy-Item $SourcePath -Destination $OnnxPath
        Write-Host "✓ Model copied successfully" -ForegroundColor Green
    } else {
        Write-Host "✗ Model not found in Model folder either!" -ForegroundColor Red
        Write-Host "Please run download_yolo_model.py first" -ForegroundColor Yellow
        exit 1
    }
} else {
    $Size = (Get-Item $OnnxPath).Length / 1MB
    Write-Host "✓ ONNX model found ($([math]::Round($Size, 2)) MB)" -ForegroundColor Green
}

Write-Host ""
Write-Host "Starting build process..." -ForegroundColor Yellow
Write-Host ""

# Clean previous build
Write-Host "[1/3] Cleaning previous build..." -ForegroundColor Cyan
.\gradlew clean
if ($LASTEXITCODE -ne 0) {
    Write-Host "✗ Clean failed!" -ForegroundColor Red
    exit 1
}
Write-Host "✓ Clean complete" -ForegroundColor Green
Write-Host ""

# Build debug APK
Write-Host "[2/3] Building debug APK..." -ForegroundColor Cyan
Write-Host "This may take 2-5 minutes on first build..." -ForegroundColor Yellow
.\gradlew assembleDebug
if ($LASTEXITCODE -ne 0) {
    Write-Host "✗ Build failed!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Common solutions:" -ForegroundColor Yellow
    Write-Host "1. Sync Gradle in Android Studio" -ForegroundColor White
    Write-Host "2. Check for errors in Kotlin files" -ForegroundColor White
    Write-Host "3. Verify all dependencies are available" -ForegroundColor White
    exit 1
}
Write-Host "✓ Build complete" -ForegroundColor Green
Write-Host ""

# Verify APK
Write-Host "[3/3] Verifying APK..." -ForegroundColor Cyan
$ApkPath = "app\build\outputs\apk\debug\app-debug.apk"

if (Test-Path $ApkPath) {
    $ApkSize = (Get-Item $ApkPath).Length / 1MB
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host "   ✓ APK BUILT SUCCESSFULLY!" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "APK Location:" -ForegroundColor Yellow
    Write-Host "  $ApkPath" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "APK Size: $([math]::Round($ApkSize, 2)) MB" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Next Steps:" -ForegroundColor Yellow
    Write-Host "  1. Transfer APK to your phone" -ForegroundColor White
    Write-Host "  2. Enable 'Install from Unknown Sources'" -ForegroundColor White
    Write-Host "  3. Open APK file on phone to install" -ForegroundColor White
    Write-Host ""
    Write-Host "OR use ADB:" -ForegroundColor Yellow
    Write-Host "  adb install $ApkPath" -ForegroundColor White
    Write-Host ""
    Write-Host "Don't forget to start the Python API server!" -ForegroundColor Cyan
    Write-Host "  cd Model" -ForegroundColor White
    Write-Host "  .\start_server.ps1" -ForegroundColor White
    Write-Host ""
    
    # Open folder
    $Response = Read-Host "Open APK folder? (y/n)"
    if ($Response -eq "y") {
        explorer.exe (Split-Path -Parent $ApkPath)
    }
    
} else {
    Write-Host "✗ APK not found!" -ForegroundColor Red
    Write-Host "Build may have failed. Check output above for errors." -ForegroundColor Yellow
    exit 1
}
