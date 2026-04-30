/*
 * Project: wM-Bus Receiver for Kamstrup FlowIQ 2200
 * Description: Specialized receiver for CI=0x79 (Compact) frames using ESP32 & CC1101.
 * Features: 
 * - Hardware Interrupt (GDO0) for non-blocking reception (WiFi/MQTT friendly).
 * - Fixed Packet Length mode to avoid FIFO overflows.
 * - Real-time AES-128 decryption and EN 13757 CRC-16 validation.
 * - Pre-filtering to discard long CI=0x78 (Full) frames without processing.
 * - WiFi with BSSID-scan (always connects to strongest AP of the same SSID).
 * - Non-blocking MQTT publish via PubSubClient (auto-reconnect).
 * - Pending-flag: packets are received even without WiFi, latest values
 *   are published automatically once the connection is restored.
 *
 * Libraries: Crypto (Rhys Weatherley), CC1101_ESP_Arduino (LSatan), PubSubClient
 */

#include <SPI.h>
#include <Crypto.h>
#include <AES.h>
#include <CTR.h>
#include <CC1101_ESP_Arduino.h>
#include <WiFi.h>
#include <PubSubClient.h>

// =============================================================================
// CONFIGURATION
// =============================================================================

// WiFi credentials – all Access Points must share the same SSID (Mesh/Repeater)
const char* WIFI_SSID     = "";
const char* WIFI_PASSWORD = "";

// MQTT Broker
const char* MQTT_SERVER    = "192.168.0.xx";  // IP of your broker
const uint16_t MQTT_PORT   = 1883;
const char* MQTT_USER      = "";               // leave empty if no auth required
const char* MQTT_PASS      = "";
const char* MQTT_CLIENT_ID = "kamstrup_flowiq";

// MQTT Topic Prefix – all topics will be e.g. "wasserzaehler/total_m3"
const char* MQTT_PREFIX    = "wasserzaehler";

// Replace with your 4-byte Meter ID (usually found on the meter housing)
const uint8_t meterId[4] = { 0x53, 0x65, 0x19, 0x38 };

// Replace with your individual 16-byte AES key provided by the utility
const uint8_t key[16] = {
  0x61, 0xDC, 0x4B, 0xC4, 0x83, 0x3D, 0xAA, 0x24,
  0xD8, 0xDA, 0x11, 0xBC, 0x47, 0xFA, 0xAE, 0xD3
};

// Set to 1 to bypass Meter-ID check and display all intercepted traffic
#define PROMISCUOUS_MODE 0



// =============================================================================
// HARDWARE DEFINITIONS (ESP32 Standard SPI)
// =============================================================================
#define CC1101_CSN   5
#define CC1101_MOSI  23
#define CC1101_MISO  19
#define CC1101_SCK   18
#define CC1101_GDO0  27   // Pin for Hardware Interrupt
#define PIN_LED       2

// =============================================================================
// CC1101 CONSTANTS & GLOBALS
// =============================================================================
#define CC1101_RXFIFO    0x3F
#define CC1101_RXBYTES   0x3B
#define CC1101_SCAL      0x33
#define CC1101_SIDLE     0x36
#define CC1101_SFRX      0x3A
#define CC1101_MARCSTATE 0x35
#define MARCSTATE_RX     0x0D

CC1101 cc1101(CC1101_SCK, CC1101_MISO, CC1101_MOSI, CC1101_CSN, CC1101_GDO0, -1);

// Global buffers and counters
static uint8_t  g_payload[64];
static uint32_t g_pktTotal   = 0;
static uint32_t g_pktCI79    = 0;
static uint32_t g_pktIgnored = 0;

// AES Decryption context
CTR<AESSmall128> aes128;
static uint8_t g_plain[128];
static uint8_t g_iv[16];

// =============================================================================
// GLOBAL MEASUREMENT VARIABLES
// (accessible from WiFi/MQTT/Webserver code anywhere in the sketch)
// =============================================================================
float    g_total_m3        = 0.0f;  // Total volume [m³]
float    g_target_m3       = 0.0f;  // Target (billing) volume [m³]
char     g_target_date[11] = "";    // Target date "YYYY-MM-DD\0"
uint16_t g_flow_now        = 0;     // Current flow rate [L/h]
float    g_max_flow        = 0.0f;  // Max flow rate [m³/h]
int8_t   g_min_ext_temp    = 0;     // Min external temperature [°C]
int8_t   g_max_ext_temp    = 0;     // Max external temperature [°C]
uint32_t g_status_raw      = 0;     // Raw status word
char     g_status_str[8]   = "OK";  // Human-readable: OK/DRY/REVERSE/LEAK/BURST/ERROR
bool     g_data_valid      = false; // true once the first valid packet has been decoded
bool     g_publish_pending = false; // true = new data waiting to be sent via MQTT

// =============================================================================
// WIFI – BSSID SCAN (always picks the strongest AP of the configured SSID)
// =============================================================================
WiFiClient   wifiClient;
PubSubClient mqttClient(wifiClient);

// Reconnect-intervals (non-blocking)
static unsigned long g_lastWifiCheck = 0;
static unsigned long g_lastMqttCheck = 0;
#define WIFI_RETRY_INTERVAL  15000UL   // check WiFi state every 15 s
#define MQTT_RETRY_INTERVAL   5000UL   // retry MQTT connect every  5 s

// Helper: build a full MQTT topic from suffix
static char g_topic[64];
static const char* makeTopic(const char* suffix) {
  snprintf(g_topic, sizeof(g_topic), "%s/%s", MQTT_PREFIX, suffix);
  return g_topic;
}

// Scans for all BSSIDs that advertise WIFI_SSID and connects to the strongest.
// The BSSID is copied into a local buffer BEFORE scanDelete() is called –
// this avoids the LoadProhibited crash caused by a dangling pointer.
static void wifiConnect() {
  WiFi.mode(WIFI_STA);
  WiFi.disconnect(true);
  delay(100);

  Serial.println("[WiFi] Scanning for access points...");
  int n = WiFi.scanNetworks(/*async=*/false, /*show_hidden=*/false);

  uint8_t  bestBSSID[6]  = {0};
  int32_t  bestRSSI      = -999;
  bool     found         = false;

  if (n > 0) {
    for (int i = 0; i < n; i++) {
      if (WiFi.SSID(i) == WIFI_SSID) {
        Serial.printf("[WiFi]   Found AP: BSSID=%s  RSSI=%d dBm  Ch=%d\n",
                      WiFi.BSSIDstr(i).c_str(), WiFi.RSSI(i), WiFi.channel(i));
        if (WiFi.RSSI(i) > bestRSSI) {
          bestRSSI = WiFi.RSSI(i);
          // Copy BSSID bytes now, while scan results are still valid
          memcpy(bestBSSID, WiFi.BSSID(i), 6);
          found = true;
        }
      }
    }
  }

  // Free scan memory AFTER all data has been copied
  WiFi.scanDelete();

  if (found) {
    Serial.printf("[WiFi] Best AP: %02X:%02X:%02X:%02X:%02X:%02X  RSSI=%d dBm\n",
                  bestBSSID[0], bestBSSID[1], bestBSSID[2],
                  bestBSSID[3], bestBSSID[4], bestBSSID[5], bestRSSI);
    Serial.printf("[WiFi] Connecting to \"%s\" (targeted BSSID)...\n", WIFI_SSID);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD, /*channel=*/0, bestBSSID);
  } else {
    // Fallback: connect without BSSID preference
    Serial.printf("[WiFi] SSID \"%s\" not found – connecting without BSSID preference...\n", WIFI_SSID);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  }
}

// Non-blocking WiFi watchdog – called every loop iteration.
// Re-scans and reconnects when the connection is lost.
static void wifiLoop() {
  if (millis() - g_lastWifiCheck < WIFI_RETRY_INTERVAL) return;
  g_lastWifiCheck = millis();

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("[WiFi] Connection lost – reconnecting (with scan)...");
    wifiConnect();
  }
}

// =============================================================================
// MQTT – NON-BLOCKING RECONNECT & PUBLISH
// =============================================================================

// Non-blocking MQTT watchdog – called every loop iteration.
// Reconnects when disconnected, then publishes pending measurement data.
static void mqttLoop() {
  // No point in trying without WiFi
  if (WiFi.status() != WL_CONNECTED) return;

  if (!mqttClient.connected()) {
    if (millis() - g_lastMqttCheck < MQTT_RETRY_INTERVAL) return;
    g_lastMqttCheck = millis();

    Serial.printf("[MQTT] Connecting to %s:%u ...\n", MQTT_SERVER, MQTT_PORT);
    bool ok = (strlen(MQTT_USER) > 0)
              ? mqttClient.connect(MQTT_CLIENT_ID, MQTT_USER, MQTT_PASS)
              : mqttClient.connect(MQTT_CLIENT_ID);

    if (ok) {
      Serial.println("[MQTT] Connected!");
    } else {
      Serial.printf("[MQTT] Failed rc=%d – retry in %lus\n",
                    mqttClient.state(), MQTT_RETRY_INTERVAL / 1000);
      return;
    }
  }

  mqttClient.loop(); // PubSubClient internal keepalive

  // Publish pending measurement values (set by processPacket())
  if (g_publish_pending) {
    char buf[32];

    snprintf(buf, sizeof(buf), "%.3f", g_total_m3);
    mqttClient.publish(makeTopic("total_m3"), buf, /*retain=*/true);

    snprintf(buf, sizeof(buf), "%.3f", g_target_m3);
    mqttClient.publish(makeTopic("target_m3"), buf, true);

    mqttClient.publish(makeTopic("target_date"), g_target_date, true);

    snprintf(buf, sizeof(buf), "%u", g_flow_now);
    mqttClient.publish(makeTopic("flow_now"), buf, true);

    snprintf(buf, sizeof(buf), "%.3f", g_max_flow);
    mqttClient.publish(makeTopic("max_flow"), buf, true);

    snprintf(buf, sizeof(buf), "%d", g_min_ext_temp);
    mqttClient.publish(makeTopic("min_ext_temp"), buf, true);

    snprintf(buf, sizeof(buf), "%d", g_max_ext_temp);
    mqttClient.publish(makeTopic("max_ext_temp"), buf, true);

    mqttClient.publish(makeTopic("status"), g_status_str, true);

    snprintf(buf, sizeof(buf), "0x%08X", (unsigned)g_status_raw);
    mqttClient.publish(makeTopic("status_raw"), buf, true);

    Serial.println("[MQTT] All values published.");
    g_publish_pending = false;
  }
}

// =============================================================================
// INTERRUPT HANDLING
// =============================================================================

// Volatile flag to signal the main loop that a packet has been received.
// Marked 'volatile' because it's changed inside the ISR.
volatile bool g_packetReady = false;

// Interrupt Service Routine (ISR) - Stored in RAM for maximum speed.
// Triggered when CC1101 GDO0 pin goes LOW (End of packet).
void IRAM_ATTR GDO0_ISR() {
  g_packetReady = true;
}

// =============================================================================
// CRYPTO & UTILITY FUNCTIONS
// =============================================================================

// Helper to print data in Hex format for debugging
static void printHex(const uint8_t* data, size_t len, const char* prefix = nullptr) {
  if (prefix) Serial.print(prefix);
  for (size_t i = 0; i < len; i++) Serial.printf("%02X ", data[i]);
  Serial.println();
}

// CRC-16 calculation according to EN 13757-4
static uint16_t crc16_en13757(const uint8_t* data, size_t len) {
  uint16_t crc = 0x0000;
  for (size_t i = 0; i < len; i++) {
    crc ^= (uint16_t)(data[i] << 8);
    for (uint8_t bit = 0; bit < 8; bit++)
      crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x3D65) : (uint16_t)(crc << 1);
  }
  return ~crc;
}

// Validates if the received packet belongs to the configured meter
static bool checkMeterId(const uint8_t* payload, uint8_t len) {
  if (len < 7) return false;
  for (uint8_t i = 0; i < 4; i++) {
    if (meterId[i] != payload[6 - i]) return false;
  }
  return true;
}

// Decrypts the wM-Bus payload using AES-128 in CTR mode
static bool decryptPayload(const uint8_t* payload, uint8_t payLen, uint8_t* plainOut, uint8_t& plainLen) {
  if (payLen < 18) return false;
  plainLen = payLen - 2 - 16; // Adjust for Link Layer overhead and Padding
  if (plainLen == 0 || plainLen > 100) return false;

  // Build Initialization Vector (IV) from packet data
  memset(g_iv, 0, sizeof(g_iv));
  memcpy(g_iv, &payload[1], 8);
  g_iv[8] = payload[10];
  memcpy(&g_iv[9], &payload[12], 4);

  aes128.setKey(key, 16);
  aes128.setIV(g_iv, 16);
  aes128.decrypt(plainOut, &payload[16], plainLen);
  return true;
}

// =============================================================================
// PACKET PROCESSING
// =============================================================================

// Main parser for validated CI=0x79 Compact Frames
static void processPacket(const uint8_t* payload, uint8_t payLen, int rssi) {
  g_pktTotal++;
  Serial.printf("\n====== Packet #%lu  RSSI=%d dBm ======\n",
                (unsigned long)g_pktTotal, (int)rssi);

  uint8_t llCI = (payLen > 9) ? payload[9] : 0;
  Serial.printf("[RAW] Len=%u  Link-CI=0x%02X\n", payLen, llCI);
  printHex(payload, payLen, "[RAW] ");

#if !PROMISCUOUS_MODE
  if (!checkMeterId(payload, payLen)) {
    Serial.println("[ID]  Foreign Meter-ID. Ignored.");
    return;
  }
#endif
  Serial.println("[ID]  Meter-ID check OK");

  uint8_t plainLen = 0;
  if (!decryptPayload(payload, payLen, g_plain, plainLen)) {
    Serial.println("[DEC] Decryption failed");
    return;
  }

  uint8_t appCI = g_plain[2];
  Serial.printf("[DEC] Application-CI=0x%02X  plainLen=%u\n", appCI, plainLen);
  printHex(g_plain, plainLen, "[DEC] ");

  // Validate data integrity via CRC comparison
  uint16_t readCrc = (uint16_t)g_plain[0] | ((uint16_t)g_plain[1] << 8);
  uint16_t calcCrc = crc16_en13757(&g_plain[2], plainLen - 2);
  bool crcOk = (calcCrc == readCrc);

  Serial.printf("[CRC] read=0x%04X  calc=0x%04X  %s\n", readCrc, calcCrc, crcOk ? "OK" : "ERROR");
  if (!crcOk) return;

  if (appCI != 0x79) {
    Serial.printf("[CI]  Unexpected Application-CI: 0x%02X. Aborting.\n", appCI);
    return;
  }

  g_pktCI79++;
  Serial.println("[CI]  Compact Frame (0x79) - confirmed");

  // --- DATA PARSING (EN 13757 DIF/VIF Records) ---
  g_status_raw = (uint32_t)g_plain[7]  | ((uint32_t)g_plain[8]  << 8)
               | ((uint32_t)g_plain[9]  << 16) | ((uint32_t)g_plain[10] << 24);

  uint32_t targetL = (uint32_t)g_plain[11] | ((uint32_t)g_plain[12] << 8)
                   | ((uint32_t)g_plain[13] << 16) | ((uint32_t)g_plain[14] << 24);
  uint16_t maxFlow  = (uint16_t)g_plain[15] | ((uint16_t)g_plain[16] << 8);
  uint16_t flowNow  = (uint16_t)g_plain[27] | ((uint16_t)g_plain[28] << 8);
  uint32_t totalL   = (uint32_t)g_plain[29] | ((uint32_t)g_plain[30] << 8)
                    | ((uint32_t)g_plain[31] << 16) | ((uint32_t)g_plain[32] << 24);

  g_min_ext_temp = (int8_t)g_plain[25];
  g_max_ext_temp = (int8_t)g_plain[26];

  // Date parsing for Target Date
  uint8_t b0 = g_plain[23], b1 = g_plain[24];
  uint8_t  tDay   = b0 & 0x1F;
  uint8_t  tMonth = b1 & 0x0F;
  uint16_t tYear  = (uint16_t)(2000 + (((b1 >> 4) << 3) | (b0 >> 5)));

  // Convert raw values to engineering units and store globally
  g_total_m3  = totalL  / 1000.0f;
  g_target_m3 = targetL / 1000.0f;
  g_flow_now  = flowNow;
  g_max_flow  = maxFlow / 1000.0f;
  snprintf(g_target_date, sizeof(g_target_date), "%04u-%02u-%02u", tYear, tMonth, tDay);

  // Human readable status mapping
  if      (g_status_raw & 0x01) strncpy(g_status_str, "DRY",     sizeof(g_status_str));
  else if (g_status_raw & 0x02) strncpy(g_status_str, "REVERSE", sizeof(g_status_str));
  else if (g_status_raw & 0x04) strncpy(g_status_str, "LEAK",    sizeof(g_status_str));
  else if (g_status_raw & 0x08) strncpy(g_status_str, "BURST",   sizeof(g_status_str));
  else if (g_status_raw != 0)   strncpy(g_status_str, "ERROR",   sizeof(g_status_str));
  else                          strncpy(g_status_str, "OK",      sizeof(g_status_str));

  // Signal the main loop that fresh data is ready to be published
  g_data_valid      = true;
  g_publish_pending = true;

  Serial.printf("[VAL] total_m3     = %u.%03u m3\n", totalL / 1000, totalL % 1000);
  Serial.printf("[VAL] target_m3    = %u.%03u m3\n", targetL / 1000, targetL % 1000);
  Serial.printf("[VAL] target_date  = %s\n",           g_target_date);
  Serial.printf("[VAL] flow_now     = %u L/h\n",      (unsigned)flowNow);
  Serial.printf("[VAL] max_flow     = %.3f m3/h\n",   g_max_flow);
  Serial.printf("[VAL] min_ext_temp = %d degC\n",     (int)g_min_ext_temp);
  Serial.printf("[VAL] max_ext_temp = %d degC\n",     (int)g_max_ext_temp);
  Serial.printf("[VAL] status       = 0x%08X  %s\n",  (unsigned)g_status_raw, g_status_str);
}

// =============================================================================
// RADIO HARDWARE CONFIGURATION
// =============================================================================
static void setupRegisters() {
  // GDO0 Config: 0x06 (Asserts on Sync word, de-asserts at end of packet)
  cc1101.spiWriteReg(0x02, 0x06);

  // FIXED PACKET LENGTH MODE
  // We cap the reception at 55 bytes. This ensures Compact frames fit perfectly
  // into the 64-byte FIFO while longer Full frames are safely truncated.
  cc1101.spiWriteReg(0x06, 55);    // PKTLEN
  cc1101.spiWriteReg(0x08, 0x00);  // PKTCTRL0: Set to Fixed Length Mode

  // 868.95 MHz Frequency Settings (wM-Bus C-Mode)
  cc1101.spiWriteReg(0x04, 0x54);  // SYNC1
  cc1101.spiWriteReg(0x05, 0x3D);  // SYNC0
  cc1101.spiWriteReg(0x0D, 0x21);  // FREQ2
  cc1101.spiWriteReg(0x0E, 0x6B);  // FREQ1
  cc1101.spiWriteReg(0x0F, 0xD0);  // FREQ0
  cc1101.spiWriteReg(0x10, 0x5C);  // MDMCFG4
  cc1101.spiWriteReg(0x11, 0x04);  // MDMCFG3
  cc1101.spiWriteReg(0x12, 0x06);  // MDMCFG2
  cc1101.spiWriteReg(0x13, 0x22);  // MDMCFG1
  cc1101.spiWriteReg(0x14, 0xF8);  // MDMCFG0
  cc1101.spiWriteReg(0x15, 0x44);  // DEVIATN
  cc1101.spiWriteReg(0x18, 0x18);  // MCSM0
  cc1101.spiWriteReg(0x19, 0x2E);  // FOCCFG
  cc1101.spiWriteReg(0x1A, 0xBF);  // BSCFG
  cc1101.spiWriteReg(0x1B, 0x43);  // AGCCTRL2
  cc1101.spiWriteReg(0x1C, 0x09);  // AGCCTRL1
  cc1101.spiWriteReg(0x1D, 0xB5);  // AGCCTRL0
  cc1101.spiWriteReg(0x21, 0xB6);  // FREND1
  cc1101.spiWriteReg(0x22, 0x10);  // FREND0
  cc1101.spiWriteReg(0x23, 0xEA);  // FSCAL3
  cc1101.spiWriteReg(0x24, 0x2A);  // FSCAL2
  cc1101.spiWriteReg(0x25, 0x00);  // FSCAL1
  cc1101.spiWriteReg(0x26, 0x1F);  // FSCAL0
}

static void cc_begin() {
  cc1101.init();
  pinMode(CC1101_GDO0, INPUT);

  uint8_t pn = cc1101.getPartnum();
  uint8_t vr = cc1101.getVersion();
  Serial.printf("[CC1101] Hardware detected: PARTNUM=0x%02X  VERSION=0x%02X\n", pn, vr);

  setupRegisters();
  cc1101.spiStrobe(CC1101_SCAL);
  delay(2);
  cc1101.setRx();

  // ATTACH INTERRUPT: Triggers on FALLING edge (when packet is fully in FIFO)
  attachInterrupt(digitalPinToInterrupt(CC1101_GDO0), GDO0_ISR, FALLING);
  Serial.println("[CC1101] ISR Mode active. Waiting for frames...");
}

// =============================================================================
// MAIN LOOP & LOGIC
// =============================================================================

static void cc_loop() {
  // Fast exit if no packet was received by the hardware interrupt
  if (!g_packetReady) return;
  g_packetReady = false;

  uint8_t bytesInFifo = cc1101.spiReadStatus(CC1101_RXBYTES) & 0x7F;

  // We expect exactly 55 bytes for a capped frame
  if (bytesInFifo >= 55) {
    // Read the entire 55-byte burst from the FIFO
    cc1101.spiReadRegBurst(CC1101_RXFIFO, g_payload, 55);

    int rssi = cc1101.getRSSI();

    // Verify wM-Bus Sync Pattern (0x54 0x3D)
    if (g_payload[0] == 0x54 && g_payload[1] == 0x3D) {

      uint8_t lByte = g_payload[2]; // Length byte (unencrypted)

      // PRE-FILTER LOGIC:
      // Compact frames (CI=0x79) always have L=52.
      // Full frames (CI=0x78) always have L=73.
      // We filter based on L-Byte to avoid processing unwanted long frames.
      if (lByte > 52) {
        g_pktIgnored++;
        Serial.printf("\n[FILTER] Discarding CI=0x78 (L=%u) | RSSI: %d dBm\n", lByte, rssi);
      } else {
        processPacket(&g_payload[3], lByte, rssi);
      }
    }
  }

  // Mandatory: Reset Radio State, Flush FIFO and return to RX mode
  cc1101.spiStrobe(CC1101_SIDLE);
  cc1101.spiStrobe(CC1101_SFRX);
  cc1101.setRx();
}

// =============================================================================
// SETUP
// =============================================================================
void setup() {
  pinMode(PIN_LED, OUTPUT);
  digitalWrite(PIN_LED, HIGH);
  Serial.begin(115200);
  delay(300);

  Serial.println("\n===== Kamstrup FlowIQ 2200 Decoder (ISR + WiFi/MQTT) =====");

  // Start WiFi: scan for strongest AP, then connect (non-blocking after this)
  wifiConnect();

  // Configure MQTT broker
  mqttClient.setServer(MQTT_SERVER, MQTT_PORT);
  mqttClient.setKeepAlive(60);

  // Initialise CC1101 radio – works independently of WiFi state
  cc_begin();

  digitalWrite(PIN_LED, LOW);
}

// =============================================================================
// LOOP
// =============================================================================
static unsigned long lastAlive = 0;

void loop() {
  
  cc_loop();
  
  wifiLoop();
  
  mqttLoop();

  // Periodic self-healing Watchdog (Every 15 seconds)
  if (millis() - lastAlive >= 15000) {
    lastAlive = millis();
    uint8_t marc = cc1101.spiReadStatus(CC1101_MARCSTATE) & 0x1F;
    Serial.printf("[ALIVE] %lus  Total:%lu  CI79:%lu  Filtered:%lu  MARC:0x%02X  WiFi:%s  MQTT:%s\n",
      millis() / 1000,
      (unsigned long)g_pktTotal,
      (unsigned long)g_pktCI79,
      (unsigned long)g_pktIgnored,
      marc,
      WiFi.status() == WL_CONNECTED ? "OK" : "GETRENNT",
      mqttClient.connected()        ? "OK" : "GETRENNT");

    // If CC1101 is NOT in RX mode (e.g., due to an unhandled overflow), reset it.
    if (marc != MARCSTATE_RX) {
      Serial.println("[ALIVE] Radio lost RX state! Restarting...");
      cc1101.spiStrobe(CC1101_SIDLE);
      cc1101.spiStrobe(CC1101_SFRX);
      cc1101.setRx();
    }
  }
}
