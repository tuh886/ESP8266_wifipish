# PhiSiFi - Enhanced WiFi Hacking Tool
<p align="center">
<a href="https://github.com/Ayushx309/PhiSiFi/"><img title="Tool" src="https://img.shields.io/badge/Tool-PhiSiFi-green"></a>
<img title="Version" src="https://img.shields.io/badge/Version-2.0-green">
<img title="Support" src="https://img.shields.io/badge/Support-Limited-yellow">
</p>

## Overview
PhiSiFi is an advanced WiFi hacking tool that combines deauthentication attacks and Evil-Twin access point techniques. This fork enhances the original [p3tr0s/PhiSiFi](https://github.com/p3tr0s/PhiSiFi) with improved UI, better device compatibility, and more effective attack methods.

<img src="https://user-images.githubusercontent.com/32341044/202444452-3e7c9ab0-1643-4996-8319-18b8c25544fa.jpg"></img><br>

## Enhanced Features
* **Simultaneous Attacks**: Run deauthentication and Evil-Twin attacks concurrently
* **Convincing Captive Portal**: Router firmware update failure disguise with professional UI
* **Credential Storage**: Save and manage up to 5 sets of captured network credentials with EEPROM persistence
* **Advanced Deauthentication**: Multiple packet types (deauth, disassociation, authentication) with adjustable intensity levels (1-5)
* **Client Targeting**: Scan for and target specific client devices on the network
* **Responsive Design**: Modern UI that works well on mobile and desktop browsers
* **Visual Feedback**: Progress indicators and animations during credential verification
* **Credential Management**: View, delete individual, or clear all stored credentials

## Advanced Captive Portal
The captive portal implementation in PhiSiFi provides a convincing and effective credential harvesting mechanism:

* **Firmware Update Disguise**: Presents as a router firmware update failure that requires network verification
* **Responsive Design**: Works well across mobile and desktop browsers with adaptive layouts
* **Professional UI Elements**:
  * Clean, modern interface with appropriate styling
  * Warning indicators that draw user attention
  * Progress animations during verification
  * Branded with the target network's SSID
* **Effective Credential Capture**:
  * Automatic password verification against the real network
  * Success/failure feedback to the user
  * Persistent storage of captured credentials in EEPROM
* **DNS Redirection**: Captures all web requests and redirects to the login portal
* **Automatic Handling**: 
  * Seamless transition between deauth attack and credential capture
  * Verification simulation with progress indicators
  * Appropriate success/failure messaging
* **Evil Twin Integration**: 
  * Automatically creates access point with target network's SSID
  * Handles client connections and redirects to the captive portal
  * Returns to normal operation after successful credential capture

## Modern User Interface
The completely redesigned UI offers a significantly improved user experience:

* **Responsive Design**: Adapts perfectly to any screen size with CSS media queries
* **Intuitive Layout**: Clear navigation with organized sections for different functions
* **Visual Feedback**: 
  * Animated loading spinners during credential verification
  * Progress bars with percentage indicators
  * Status messages that update during operations
  * Signal strength indicators with color coding
* **Professional Styling**:
  * Modern color scheme with appropriate contrast
  * Consistent typography and spacing
  * Properly sized touch targets for mobile users
  * SVG icons and visual elements
* **Improved Admin Panel**: 
  * Comprehensive dashboard for monitoring and control
  * Tabular view of captured credentials with management options
  * Attack intensity controls with visual feedback
  * Client list display with MAC addresses

## Technical Improvements
* **Enhanced Deauthentication**: 
  * Multiple packet types (deauth, disassociation, authentication failure)
  * Variable reason codes for better effectiveness against different devices
  * Adjustable packet transmission rates (100-500ms intervals)
  * Targeted client deauthentication with MAC address tracking
* **Evil Twin Implementation**:
  * Automatic SSID cloning of target networks
  * DNS redirection to captive portal
  * Automatic shutdown after credential capture
* **Efficient Memory Management**:
  * EEPROM storage for credentials (up to 5 sets)
  * Optimized packet generation for better performance
  * Efficient client scanning and tracking
* **Credential Verification**:
  * Real-time password verification against actual networks
  * Automatic testing of captured credentials
  * Success/failure feedback with appropriate messaging

## DISCLAIMER
This tool is provided for **EDUCATIONAL PURPOSES ONLY** and should only be used against your own networks and devices with proper authorization!  
Please check the legal regulations in your country before using it. Unauthorized network attacks are illegal and unethical.

## Installation Guide

### Using Arduino IDE
1. Install [Arduino IDE](https://www.arduino.cc/en/software)
2. In Arduino go to `File` -> `Preferences` add this URL to `Additional Boards Manager URLs`:
   `https://raw.githubusercontent.com/SpacehuhnTech/arduino/main/package_spacehuhn_index.json`  
3. In Arduino go to `Tools` -> `Board` -> `Boards Manager` search for and install the `deauther` package  
4. Download and open the PhiSiFi sketch with Arduino IDE
5. Select an `ESP8266 Deauther` board in Arduino under `tools` -> `board`
6. Connect your device and select the serial port in Arduino under `tools` -> `port`
7. Click Upload button

## Usage Guide

### Initial Connection
1. Power on your ESP8266 device
2. Connect to the AP named `WiFi_Setup` with password `@wifi2005309@` from your phone/PC
3. Open a web browser and navigate to `192.168.4.1` (or any website - you'll be redirected to the admin panel)

### Running Attacks
1. From the admin panel, you'll see a list of nearby WiFi networks - select your target by clicking "Select"
2. **Deauthentication Attack**:
   - Click the "Start Deauth Attack" button to begin disconnecting devices from the selected network
   - Adjust the attack intensity (1-5) in the Attack Settings panel
   - Higher intensity means more packets per second (1 = 2 packets/sec, 5 = 10 packets/sec)
   - Enable "Start Client Scan" to detect and target specific devices on the network
   
3. **Evil-Twin Attack**:
   - Click the "Start Evil Twin" button to create a fake AP with the same name as your target
   - When users try to reconnect, they'll see a "Firmware Update Failed" page requesting their WiFi password
   - The tool will verify entered passwords against the real network
   - Successfully verified passwords will be stored in EEPROM

### Credential Management
- View all stored credentials by clicking the "View Stored Credentials" button
- Delete individual credentials using the "Delete" button next to each entry
- Delete all stored credentials with the "Delete All Credentials" button
- Credentials persist through power cycles until manually deleted

### Admin Interface
- The main interface at `192.168.4.1/admin` shows:
  - List of nearby networks with signal strength indicators
  - Attack control buttons (Start/Stop Deauth, Start/Stop Evil Twin, Start/Stop Client Scan)
  - Attack settings panel for adjusting deauth intensity
  - Client list showing MAC addresses of connected devices (when scanning is enabled)
  - Stored credentials section (if any have been captured)

## Troubleshooting
- **Deauth Not Working?** Some devices and networks are resistant to deauthentication attacks. Try:
  - Increasing the attack intensity (4-5)
  - Enabling client scanning to target specific devices
  - Ensuring you're close enough to both the target AP and clients
  - Some modern devices implement protection against deauth attacks
- **Evil-Twin Not Appearing?** Make sure:
  - You've selected a target network first
  - The target network is within range
  - Your ESP8266 has sufficient power
  - Try stopping and restarting the Evil Twin
- **Password Verification Failing?** This could be due to:
  - Target network is too far away for reliable connection
  - Password complexity (very long passwords may cause issues)
  - Network has additional security measures
- **Device Not Connecting to Evil Twin?** Try:
  - Running the deauth attack simultaneously to force disconnections
  - Restarting the Evil Twin AP
  - Making sure you're close to the target clients
- **ESP8266 Crashing?** This could be due to:
  - Insufficient power supply (use a good quality USB cable and power source)
  - Running too many operations simultaneously
  - Try reducing the deauth intensity

## Credits
* Original project: [p3tr0s/PhiSiFi](https://github.com/p3tr0s/PhiSiFi)
* Fork maintained by: [Ayushx309](https://github.com/Ayushx309)
* Based on work from:
  * [SpacehuhnTech/esp8266_deauther](https://github.com/SpacehuhnTech/esp8266_deauther)
  * [M1z23R/ESP8266-EvilTwin](https://github.com/M1z23R/ESP8266-EvilTwin)
  * [adamff1/ESP8266-Captive-Portal](https://github.com/adamff1/ESP8266-Captive-Portal)

## License 
This software is licensed under the [MIT License](https://opensource.org/licenses/MIT).

## Support & Contributions
- For issues and feature requests, please open an issue on GitHub
- Contributions and improvements are welcome via pull requests
- This is a community-maintained fork with limited support

## Donation / Support / Appreciation
<a href="https://www.buymeacoffee.com/p3tr0s"><img src="https://static.vecteezy.com/system/resources/previews/025/222/157/original/shawarma-sandwich-isolated-on-transparent-background-png.png"></a>
