@echo off
title Wireshark Network Traffic Capture Helper
color 0b

echo =========================================================================
echo   Wireshark Network Traffic & User Activity Capture Helper
echo =========================================================================
echo.
echo  This tool launches Wireshark with optimal capture filters to track:
echo    - DNS Domain Lookups (UDP Port 53)
echo    - Encrypted HTTPS TLS SNI Handshakes (TCP Port 443)
echo    - Cleartext HTTP Host Headers (TCP Port 80)
echo.
echo  Steps:
echo    1. Wireshark will open. Double-click your active Wi-Fi or Hotspot adapter.
echo    2. Browse any websites on this computer or other connected devices.
echo    3. Click the red Stop button in Wireshark.
echo    4. Go to: File -> Save As -> "capture.pcap"
echo    5. Drag and drop "capture.pcap" into the SOC Dashboard at:
echo       http://localhost:8090/index.html
echo.
echo =========================================================================
echo.

if exist "C:\Program Files\Wireshark\Wireshark.exe" (
    echo Starting Wireshark with capture filter: port 53 or port 443 or port 80 ...
    start "" "C:\Program Files\Wireshark\Wireshark.exe" -k -f "port 53 or port 443 or port 80"
) else (
    echo [ERROR] Wireshark was not found at C:\Program Files\Wireshark\Wireshark.exe
    pause
)
