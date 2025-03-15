# PhiSiFi - Enhanced WiFi Hacking Tool
<p align="center">
<a href="https://github.com/Ayushx309/PhiSiFi/"><img title="Tool" src="https://img.shields.io/badge/Tool-PhiSiFi-green"></a>
<img title="Version" src="https://img.shields.io/badge/Version-2.0-green">
<img title="Support" src="https://img.shields.io/badge/Support-Limited-yellow">
</p>

## Overview
PhiSiFi is an advanced WiFi security testing tool that combines deauthentication attacks and Evil-Twin access point techniques. This fork enhances the original [p3tr0s/PhiSiFi](https://github.com/p3tr0s/PhiSiFi) with improved UI, better device compatibility, and more effective attack methods.

<img src="https://user-images.githubusercontent.com/32341044/202444452-3e7c9ab0-1643-4996-8319-18b8c25544fa.jpg"></img><br>

## Enhanced Features
* **Simultaneous Attacks**: Run deauthentication and Evil-Twin attacks concurrently without toggling
* **Improved Captive Portal**: Enhanced UI with device-specific optimizations for iOS, Android, and other devices
* **Credential Storage**: Save and manage captured network credentials with EEPROM persistence
* **Advanced Deauthentication**: Multiple deauth methods with adjustable intensity levels (1-5)
* **Client Targeting**: Scan for and target specific client devices on the network
* **Responsive Design**: Modern UI that works well on mobile and desktop browsers
* **Progress Indicators**: Visual feedback during credential verification
* **Enhanced Compatibility**: Better handling of different captive portal detection mechanisms

## Advanced Captive Portal
The enhanced captive portal in this fork provides several significant improvements:

* **Multi-Platform Detection**: Automatically detects and responds to captive portal requests from various devices:
  * Android: connectivitycheck.gstatic.com, clients3.google.com, generate_204
  * iOS: captive.apple.com, www.apple.com, www.appleiphonecell.com
  * Windows: ncsi.txt and other Microsoft-specific endpoints
* **Device-Specific Optimizations**: Tailors the experience based on the connecting device:
  * iOS-specific headers (X-Apple-MobileWeb-App-Capable, X-Apple-Touch-Fullscreen)
  * Android-specific redirects and response handling
  * User-Agent detection for platform-specific enhancements
* **HTTPS Handling**: Properly handles HTTPS requests with informative redirect pages
* **DNS Caching**: Implements efficient DNS caching to improve performance and reduce latency
* **Automatic Redirects**: Users are automatically directed to the login page regardless of the URL they enter

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
  * Variable reason codes for better effectiveness
  * Adjustable packet transmission rates
  * Targeted client deauthentication
* **Optimized WiFi Configuration**:
  * Maximum power output (20.5 dBm)
  * 802.11n mode for better performance
  * Channel matching with target networks
* **Efficient Memory Management**:
  * EEPROM storage for credentials (up to 5 sets)
  * DNS caching to improve performance
  * Optimized packet generation
* **Improved Security**:
  * Password verification against real networks
  * Secure credential storage and management
  * Protection against common exploits

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
3. Open a web browser and navigate to `192.168.4.1` (or any website - you'll be redirected to the captive portal)

### Running Attacks
1. Select the target AP you want to attack from the list (refreshes every 30 seconds)
2. **Deauthentication Attack**:
   - Click the "Start Deauth Attack" button to begin kicking devices off the selected network
   - Adjust the attack intensity using the slider (1-5) in the Attack Settings panel
   - Enable "Start Client Scan" to detect and target specific devices on the network
   - View connected clients in the Client List section
   
3. **Evil-Twin Attack**:
   - Click the "Start Evil Twin" button to create a fake AP with the same name as your target
   - When users try to reconnect, they'll be presented with a login page requesting their WiFi password
   - The tool will verify entered passwords against the real network
   - Successfully verified passwords will be stored automatically

### Admin Access
- Access the admin panel at `192.168.4.1/admin` while connected to the AP
- View and manage stored credentials at `192.168.4.1/stored`
- Stop any running attacks from the admin panel
- Adjust attack settings and view connected clients

### Credential Management
- Successfully captured credentials will be displayed and stored in EEPROM
- View all stored credentials in the admin panel at `/stored`
- Delete individual credentials or all credentials from the management interface
- Credentials persist through power cycles until manually deleted

## Troubleshooting
- **Deauth Not Working?** Some devices and networks are resistant to deauthentication attacks. Try:
  - Increasing the attack intensity (4-5)
  - Enabling client scanning to target specific devices
  - Ensuring you're on the correct channel
- **Evil-Twin Not Appearing?** Make sure you've selected a target network first and that your device has sufficient power.
- **Captive Portal Issues?** Different devices handle captive portals differently. The tool includes optimizations for various platforms, but some devices may behave unexpectedly.
- **HTTPS Warnings?** The captive portal will redirect HTTPS requests to HTTP with an explanation page.

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
