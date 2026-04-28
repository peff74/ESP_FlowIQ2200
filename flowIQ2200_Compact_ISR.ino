/*
 * Project: wM-Bus Receiver for Kamstrup FlowIQ 2200
 * Description: Specialized receiver for CI=0x79 (Compact) frames using ESP32 & CC1101.
 * Features: 
 * - Hardware Interrupt (GDO0) for non-blocking reception (WiFi/MQTT friendly).
 * - Fixed Packet Length mode to avoid FIFO overflows.
 * - Real-time AES-128 decryption and EN 13757 CRC-16 validation.
 * - Pre-filtering to discard long CI=0x78 (Full) frames without processing.
 * * Libraries: Crypto (Rhys Weatherley), CC1101_ESP_Arduino (LSatan)
 */

#include <SPI.h>
#include <Crypto.h>
#include <AES.h>
#include <CTR.h>
#include <CC1101_ESP_Arduino.h>

// =============================================================================
// CONFIGURATION
// =============================================================================

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
  uint32_t status  = (uint32_t)g_plain[7]  | ((uint32_t)g_plain[8]  << 8) | ((uint32_t)g_plain[9]  << 16) | ((uint32_t)g_plain[10] << 24);
  uint32_t targetL = (uint32_t)g_plain[11] | ((uint32_t)g_plain[12] << 8) | ((uint32_t)g_plain[13] << 16) | ((uint32_t)g_plain[14] << 24);
  uint16_t maxFlow = (uint16_t)g_plain[15] | ((uint16_t)g_plain[16] << 8);
  uint16_t flowNow = (uint16_t)g_plain[27] | ((uint16_t)g_plain[28] << 8);
  uint32_t totalL  = (uint32_t)g_plain[29] | ((uint32_t)g_plain[30] << 8) | ((uint32_t)g_plain[31] << 16) | ((uint32_t)g_plain[32] << 24);
  
  int8_t minTemp = (int8_t)g_plain[25];
  int8_t maxTemp = (int8_t)g_plain[26];
  
  // Date parsing for Target Date
  uint8_t b0 = g_plain[23], b1 = g_plain[24];
  uint8_t tDay = b0 & 0x1F, tMonth = b1 & 0x0F;
  uint16_t tYear = (uint16_t)(2000 + (((b1 >> 4) << 3) | (b0 >> 5)));

  // Human readable status mapping
  const char* ss = "OK";
  if      (status & 0x01) ss = "DRY";
  else if (status & 0x02) ss = "REVERSE";
  else if (status & 0x04) ss = "LEAK";
  else if (status & 0x08) ss = "BURST";
  else if (status != 0)   ss = "ERROR";

  Serial.printf("[VAL] total_m3     = %u.%03u m3\n", totalL / 1000, totalL % 1000);
  Serial.printf("[VAL] target_m3    = %u.%03u m3\n", targetL / 1000, targetL % 1000);
  Serial.printf("[VAL] target_date  = %04u-%02u-%02u\n", tYear, tMonth, tDay);
  Serial.printf("[VAL] flow_now     = %u L/h\n", (unsigned)flowNow);
  Serial.printf("[VAL] max_flow     = %.3f m3/h\n", maxFlow / 1000.0f);
  Serial.printf("[VAL] min_ext_temp = %d degC\n", (int)minTemp);
  Serial.printf("[VAL] max_ext_temp = %d degC\n", (int)maxTemp);
  Serial.printf("[VAL] status       = 0x%08X  %s\n", (unsigned)status, ss);
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

void setup() {
  pinMode(PIN_LED, OUTPUT);
  digitalWrite(PIN_LED, HIGH);
  Serial.begin(115200);
  delay(300);

  Serial.println("\n===== Kamstrup FlowIQ 2200 Decoder (ISR-Version) =====");
  cc_begin();
  
  digitalWrite(PIN_LED, LOW);
}

static unsigned long lastAlive = 0;

void loop() {
  // High-priority call to check the ISR flag. Runs in sub-microseconds.
  cc_loop();

  // Placeholder: Add WiFi/MQTT logic here. They won't block the CC1101 reception.

  // Periodic self-healing Watchdog (Every 15 seconds)
  if (millis() - lastAlive >= 15000) {
    lastAlive = millis();
    uint8_t marc = cc1101.spiReadStatus(CC1101_MARCSTATE) & 0x1F;
    Serial.printf("[ALIVE] %lus  Total:%lu  CI79:%lu  Filtered:%lu  MARC:0x%02X\n",
      millis() / 1000, (unsigned long)g_pktTotal, (unsigned long)g_pktCI79, (unsigned long)g_pktIgnored, marc);

    // If CC1101 is NOT in RX mode (e.g., due to an unhandled overflow), reset it.
    if (marc != MARCSTATE_RX) {
      Serial.println("[ALIVE] Radio lost RX state! Restarting...");
      cc1101.spiStrobe(CC1101_SIDLE);
      cc1101.spiStrobe(CC1101_SFRX);
      cc1101.setRx();
    }
  }
}