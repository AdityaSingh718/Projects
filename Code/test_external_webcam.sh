#!/bin/bash

# External USB Webcam Test Script
# For QIDK Pose Detection App

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     External USB Webcam Test Script - QIDK Pose App         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if ADB is available
if ! command -v adb &> /dev/null; then
    echo -e "${RED}❌ ERROR: adb command not found${NC}"
    echo "Please install Android SDK Platform Tools"
    exit 1
fi

# Check if device is connected
echo -e "${BLUE}[1/8]${NC} Checking ADB connection..."
DEVICE_COUNT=$(adb devices | grep -w device | wc -l)
if [ "$DEVICE_COUNT" -eq 0 ]; then
    echo -e "${RED}❌ No device connected${NC}"
    echo "Please connect your QIDK device via USB"
    exit 1
else
    echo -e "${GREEN}✅ Device connected${NC}"
fi

echo ""

# Check USB devices
echo -e "${BLUE}[2/8]${NC} Checking USB devices..."
echo "USB Devices:"
adb shell lsusb 2>/dev/null | while read line; do
    if [[ $line == *"Camera"* ]] || [[ $line == *"Webcam"* ]] || [[ $line == *"Video"* ]]; then
        echo -e "  ${GREEN}✅ $line${NC}"
    else
        echo "  $line"
    fi
done

echo ""

# Check video devices
echo -e "${BLUE}[3/8]${NC} Checking video devices..."
VIDEO_DEVICES=$(adb shell ls /dev/video* 2>/dev/null)
if [ -z "$VIDEO_DEVICES" ]; then
    echo -e "${YELLOW}⚠️  No video devices found${NC}"
else
    echo "Video Devices:"
    echo "$VIDEO_DEVICES" | while read line; do
        echo -e "  ${GREEN}✅ $line${NC}"
    done
fi

echo ""

# Check if app is installed
echo -e "${BLUE}[4/8]${NC} Checking if app is installed..."
APP_INSTALLED=$(adb shell pm list packages | grep "com.example.eswproject")
if [ -z "$APP_INSTALLED" ]; then
    echo -e "${YELLOW}⚠️  App not installed${NC}"
    echo "Install with: ./gradlew installDebug"
else
    echo -e "${GREEN}✅ App installed${NC}"
fi

echo ""

# Check camera permissions
echo -e "${BLUE}[5/8]${NC} Checking camera permissions..."
CAMERA_PERMISSION=$(adb shell dumpsys package com.example.eswproject 2>/dev/null | grep "android.permission.CAMERA" | head -1)
if [[ $CAMERA_PERMISSION == *"granted=true"* ]]; then
    echo -e "${GREEN}✅ Camera permission granted${NC}"
else
    echo -e "${YELLOW}⚠️  Camera permission not granted or app not installed${NC}"
fi

echo ""

# Check USB host support
echo -e "${BLUE}[6/8]${NC} Checking USB host support..."
USB_HOST=$(adb shell pm list features 2>/dev/null | grep "android.hardware.usb.host")
if [ -z "$USB_HOST" ]; then
    echo -e "${RED}❌ USB host not supported${NC}"
else
    echo -e "${GREEN}✅ USB host supported${NC}"
fi

echo ""

# Summary
echo -e "${BLUE}[7/8]${NC} Summary:"
echo "════════════════════════════════════════════════"

# Count cameras
FRONT_CAMERA=$(adb shell dumpsys media.camera 2>/dev/null | grep -i "camera 0" | grep -i "front")
BACK_CAMERA=$(adb shell dumpsys media.camera 2>/dev/null | grep -i "camera 1" | grep -i "back")
EXTERNAL_CAMERA=$(adb shell dumpsys media.camera 2>/dev/null | grep -i "external")

echo -n "Cameras detected: "
CAMERA_COUNT=0
if [ ! -z "$FRONT_CAMERA" ]; then ((CAMERA_COUNT++)); fi
if [ ! -z "$BACK_CAMERA" ]; then ((CAMERA_COUNT++)); fi
if [ ! -z "$EXTERNAL_CAMERA" ]; then ((CAMERA_COUNT++)); fi

if [ "$CAMERA_COUNT" -eq 0 ]; then
    echo -e "${YELLOW}⚠️  Unable to determine (app may need to run first)${NC}"
else
    echo -e "${GREEN}$CAMERA_COUNT camera(s)${NC}"
fi

# USB Webcam status
if [[ $(adb shell lsusb 2>/dev/null) == *"Camera"* ]] || [[ $(adb shell lsusb 2>/dev/null) == *"Webcam"* ]]; then
    echo -e "USB Webcam: ${GREEN}✅ Connected${NC}"
    USB_WEBCAM_CONNECTED=true
else
    echo -e "USB Webcam: ${YELLOW}❌ Not detected${NC}"
    USB_WEBCAM_CONNECTED=false
fi

echo ""

# Testing recommendations
echo -e "${BLUE}[8/8]${NC} Testing Recommendations:"
echo "════════════════════════════════════════════════"

if [ "$USB_WEBCAM_CONNECTED" = true ]; then
    echo -e "${GREEN}✅ USB Webcam detected - Ready for external camera testing${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Launch the app"
    echo "  2. Monitor logs: adb logcat | grep CameraHelper"
    echo "  3. Look for: 'Using external USB camera' in logs"
    echo "  4. Verify camera preview shows webcam feed"
    echo "  5. Test pose detection by standing in front of webcam"
else
    echo -e "${YELLOW}⚠️  No USB webcam detected${NC}"
    echo ""
    echo "Options:"
    echo "  A. Connect USB webcam:"
    echo "     - Use USB OTG cable"
    echo "     - Connect webcam to QIDK"
    echo "     - Re-run this script"
    echo "  B. Use built-in camera:"
    echo "     - App will automatically use device camera"
    echo "     - No changes needed"
fi

echo ""
echo "════════════════════════════════════════════════"

# Live log monitoring option
echo ""
echo -e "${BLUE}Would you like to monitor live logs now?${NC} [y/N]"
read -n 1 -r -t 10 REPLY
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "Monitoring logs (press Ctrl+C to stop)..."
    echo "════════════════════════════════════════════════"
    adb logcat | grep -E "CameraHelper|Camera|YoloPoseAnalyzer|PostureDetector" --line-buffered | while read line; do
        if [[ $line == *"external"* ]] || [[ $line == *"External"* ]]; then
            echo -e "${GREEN}$line${NC}"
        elif [[ $line == *"error"* ]] || [[ $line == *"Error"* ]] || [[ $line == *"ERROR"* ]]; then
            echo -e "${RED}$line${NC}"
        elif [[ $line == *"warning"* ]] || [[ $line == *"Warning"* ]]; then
            echo -e "${YELLOW}$line${NC}"
        else
            echo "$line"
        fi
    done
else
    echo ""
    echo "To monitor logs later, run:"
    echo "  adb logcat | grep -E \"CameraHelper|Camera|YoloPoseAnalyzer\""
fi

echo ""
echo -e "${GREEN}Test complete!${NC}"
