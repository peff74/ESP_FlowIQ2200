/*
  WMBus_Diag - wM-Bus C-Mode receiver, CI=0x79 (Compact Frame) only.
  No WiFi, no MQTT.

  Libraries: Crypto (rweather), CC1101_ESP_Arduino
  Board:     ESP32 Dev Module
*/

// =============================================================================
// CONFIGURATION
// =============================================================================
const uint8_t meterId[4] = { 0x53, 0x65, 0x19, 0x38 };

const uint8_t key[16] = {
  0x61, 0xDC, 0x4B, 0xC4,
  0x83, 0x3D, 0xAA, 0x24,
  0xD8, 0xDA, 0x11, 0xBC,
  0x47, 0xFA, 0xAE, 0xD3
};

// 1 = skip Meter-ID check, dump every received frame
#define PROMISCUOUS_MODE 0

// =============================================================================
// HARDWARE PINS (ESP32)
// =============================================================================
#define CC1101_CSN   5
#define CC1101_MOSI  23
#define CC1101_MISO  19
#define CC1101_SCK   18
#define CC1101_GDO0  27   // HIGH on sync word, LOW on end of packet
#define PIN_LED       2

// =============================================================================
// INCLUDES
// =============================================================================
#include <SPI.h>
#include <Crypto.h>
#include <AES.h>
#include <CTR.h>
#include <CC1101_ESP_Arduino.h>

// =============================================================================
// CC1101 REGISTERS
// =============================================================================
#define CC1101_RXFIFO    0x3F
#define CC1101_RXBYTES   0x3B
#define CC1101_SCAL      0x33
#define CC1101_SIDLE     0x36
#define CC1101_SFRX      0x3A
#define CC1101_MARCSTATE 0x35
#define MARCSTATE_RX     0x0D

// =============================================================================
// GLOBALS
// =============================================================================
CC1101 cc1101(CC1101_SCK, CC1101_MISO, CC1101_MOSI, CC1101_CSN, CC1101_GDO0, -1);

// RX state machine
static uint8_t  g_payload[128];      // CI=0x79 frames are 55 bytes max
static uint16_t g_rxBytesTotal  = 0;
static uint16_t g_expectedTotal = 0;
static bool     g_lengthKnown   = false;
static bool     g_receiving     = false;

// Counters
static uint32_t g_pktTotal  = 0;
static uint32_t g_pktCI79   = 0;
static uint32_t g_pktOther  = 0;  // received but not CI=0x79 (counted, discarded)

// AES
CTR<AESSmall128> aes128;
static uint8_t g_plain[128];
static uint8_t g_iv[16];

// =============================================================================
// HELPERS
// =============================================================================
static void printHex(const uint8_t* data, size_t len, const char* prefix = nullptr)
{
  if (prefix) Serial.print(prefix);
  for (size_t i = 0; i < len; i++) Serial.printf("%02X ", data[i]);
  Serial.println();
}

// CRC16 EN13757 (poly 0x3D65, init 0x0000, result inverted)
// Verified: plain[0-1] = CRC(plain[2..end]) for CI=0x79
static uint16_t crc16_en13757(const uint8_t* data, size_t len)
{
  uint16_t crc = 0x0000;
  for (size_t i = 0; i < len; i++) {
    crc ^= (uint16_t)(data[i] << 8);
    for (uint8_t bit = 0; bit < 8; bit++)
      crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x3D65)
                           : (uint16_t)(crc << 1);
  }
  return ~crc;
}

static bool checkMeterId(const uint8_t* payload, uint8_t len)
{
  if (len < 7) return false;
  for (uint8_t i = 0; i < 4; i++) {
    if (meterId[i] != payload[6 - i]) {
      Serial.printf("[ID] NO MATCH  frame=%02X%02X%02X%02X  cfg=%02X%02X%02X%02X\n",
        payload[6], payload[5], payload[4], payload[3],
        meterId[3], meterId[2], meterId[1], meterId[0]);
      return false;
    }
  }
  Serial.println("[ID] Meter-ID OK");
  return true;
}

static bool decryptPayload(const uint8_t* payload, uint8_t payLen,
                            uint8_t* plainOut, uint8_t& plainLen)
{
  if (payLen < 18) { Serial.println("[DEC] Payload too short"); return false; }
  plainLen = payLen - 2 - 16;
  if (plainLen == 0 || plainLen > 100) { Serial.println("[DEC] Invalid length"); return false; }

  memset(g_iv, 0, sizeof(g_iv));
  memcpy(g_iv,     &payload[1], 8);
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
static void processPacket(const uint8_t* payload, uint8_t payLen, int16_t rssi)
{
  g_pktTotal++;
  Serial.printf("\n====== Packet #%lu  RSSI=%d dBm ======\n",
                (unsigned long)g_pktTotal, (int)rssi);

  // 1. RAW output – always first
  uint8_t llCI = (payLen > 9) ? payload[9] : 0;
  Serial.printf("[RAW] Len=%u  Link-CI=0x%02X\n", payLen, llCI);
  printHex(payload, payLen, "[RAW] ");

  // 2. Meter-ID check
#if PROMISCUOUS_MODE
  Serial.println("[ID]  PROMISCUOUS - ID check skipped");
#else
  if (!checkMeterId(payload, payLen)) return;
#endif

  // 3. Decrypt
  uint8_t plainLen = 0;
  if (!decryptPayload(payload, payLen, g_plain, plainLen)) return;
  if (plainLen < 3) { Serial.println("[DEC] Plaintext too short"); return; }

  uint8_t appCI = g_plain[2];
  Serial.printf("[DEC] Application-CI=0x%02X  plainLen=%u\n", appCI, plainLen);
  printHex(g_plain, plainLen, "[DEC] ");

  // 4. CRC check
  uint16_t readCrc = (uint16_t)g_plain[0] | ((uint16_t)g_plain[1] << 8);
  uint16_t calcCrc = crc16_en13757(&g_plain[2], plainLen - 2);
  bool     crcOk   = (calcCrc == readCrc);
  Serial.printf("[CRC] read=0x%04X  calc=0x%04X  %s\n",
                readCrc, calcCrc, crcOk ? "OK" : "FAIL - corrupt or wrong key!");
  if (!crcOk) return;

  // 5. CI=0x79 only
  if (appCI != 0x79) {
    g_pktOther++;
    Serial.printf("[CI]  Not a Compact Frame (0x%02X) - discarded\n", appCI);
    return;
  }

  // 6. Parse Compact Frame
  // Fixed offsets verified against wmbusmeters kamwater driver:
  // [0-1]   CRC               [2]     CI=0x79
  // [3-6]   format hash       [7-10]  status
  // [11-14] target_m3 (L)     [15-16] max_flow (10^-3 m3/h)
  // [17-22] vendor specific   [23-24] target_date
  // [25]    min_ext_temp      [26]    max_ext_temp
  // [27-28] flow_now (L/h)    [29-32] total_m3 (L)
  if (plainLen < 33) { Serial.println("[CI] Compact Frame too short!"); return; }
  g_pktCI79++;
  Serial.println("[CI]  Compact Frame (0x79) - FlowIQ 2200");

  uint32_t status  = (uint32_t)g_plain[7]  | ((uint32_t)g_plain[8]  << 8)
                   | ((uint32_t)g_plain[9]  << 16) | ((uint32_t)g_plain[10] << 24);
  uint32_t targetL = (uint32_t)g_plain[11] | ((uint32_t)g_plain[12] << 8)
                   | ((uint32_t)g_plain[13] << 16) | ((uint32_t)g_plain[14] << 24);
  uint16_t maxFlow = (uint16_t)g_plain[15] | ((uint16_t)g_plain[16] << 8);
  uint16_t flowNow = (uint16_t)g_plain[27] | ((uint16_t)g_plain[28] << 8);
  uint32_t totalL  = (uint32_t)g_plain[29] | ((uint32_t)g_plain[30] << 8)
                   | ((uint32_t)g_plain[31] << 16) | ((uint32_t)g_plain[32] << 24);
  int8_t   minTemp = (int8_t)g_plain[25];
  int8_t   maxTemp = (int8_t)g_plain[26];

  // wM-Bus Type G date decode
  uint8_t  b0     = g_plain[23];
  uint8_t  b1     = g_plain[24];
  uint8_t  tDay   = b0 & 0x1F;
  uint8_t  tMonth = b1 & 0x0F;
  uint16_t tYear  = (uint16_t)(2000 + (((b1 >> 4) << 3) | (b0 >> 5)));

  const char* ss = "OK";
  if      (status & 0x01) ss = "DRY";
  else if (status & 0x02) ss = "REVERSE";
  else if (status & 0x04) ss = "LEAK";
  else if (status & 0x08) ss = "BURST";
  else if (status != 0)   ss = "ERROR";

  Serial.printf("[VAL] total_m3     = %u.%03u m3\n",   totalL  / 1000, totalL  % 1000);
  Serial.printf("[VAL] target_m3    = %u.%03u m3\n",   targetL / 1000, targetL % 1000);
  Serial.printf("[VAL] target_date  = %04u-%02u-%02u\n", tYear, tMonth, tDay);
  Serial.printf("[VAL] flow_now     = %u L/h  (%.3f m3/h)\n",
                (unsigned)flowNow, flowNow / 1000.0f);
  Serial.printf("[VAL] max_flow     = %.3f m3/h\n", maxFlow / 1000.0f);
  Serial.printf("[VAL] min_ext_temp = %d degC\n", (int)minTemp);
  Serial.printf("[VAL] max_ext_temp = %d degC\n", (int)maxTemp);
  Serial.printf("[VAL] status       = 0x%08X  %s\n", (unsigned)status, ss);
}

// =============================================================================
// CC1101 SETUP
// =============================================================================
static void setupRegisters()
{
  // GDO0=0x06: HIGH on sync word, LOW on end of packet
  // GDO2 not used
  // PKTCTRL0=0x02: infinite length (required for wM-Bus variable-length frames)
  // FIFOTHR=0x00: threshold 4 bytes RX (no burst needed for 55-byte frames)
  cc1101.spiWriteReg(0x00, 0x2E);  // IOCFG2: high-Z (not used)
  cc1101.spiWriteReg(0x02, 0x06);  // IOCFG0: sync word indicator
  cc1101.spiWriteReg(0x03, 0x00);  // FIFOTHR: RX threshold = 4 bytes
  cc1101.spiWriteReg(0x04, 0x54);  // SYNC1
  cc1101.spiWriteReg(0x05, 0x3D);  // SYNC0
  cc1101.spiWriteReg(0x06, 0x30);  // PKTLEN
  cc1101.spiWriteReg(0x07, 0x00);  // PKTCTRL1
  cc1101.spiWriteReg(0x08, 0x02);  // PKTCTRL0: infinite length
  cc1101.spiWriteReg(0x09, 0x00);  // ADDR
  cc1101.spiWriteReg(0x0A, 0x00);  // CHANNR
  cc1101.spiWriteReg(0x0B, 0x08);  // FSCTRL1
  cc1101.spiWriteReg(0x0C, 0x00);  // FSCTRL0
  cc1101.spiWriteReg(0x0D, 0x21);  // FREQ2  868.3 MHz
  cc1101.spiWriteReg(0x0E, 0x6B);  // FREQ1
  cc1101.spiWriteReg(0x0F, 0xD0);  // FREQ0
  cc1101.spiWriteReg(0x10, 0x5C);  // MDMCFG4  100 kBaud
  cc1101.spiWriteReg(0x11, 0x04);  // MDMCFG3
  cc1101.spiWriteReg(0x12, 0x06);  // MDMCFG2  2-FSK, 16/16 sync
  cc1101.spiWriteReg(0x13, 0x22);  // MDMCFG1
  cc1101.spiWriteReg(0x14, 0xF8);  // MDMCFG0
  cc1101.spiWriteReg(0x15, 0x44);  // DEVIATN
  cc1101.spiWriteReg(0x17, 0x00);  // MCSM1  RXOFF=IDLE
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
  cc1101.spiWriteReg(0x29, 0x59);  // FSTEST
  cc1101.spiWriteReg(0x2C, 0x81);  // TEST2
  cc1101.spiWriteReg(0x2D, 0x35);  // TEST1
  cc1101.spiWriteReg(0x2E, 0x09);  // TEST0
}

static void cc_begin()
{
  Serial.println("[CC1101] init...");
  cc1101.init();
  pinMode(CC1101_GDO0, INPUT);

  uint8_t pn = cc1101.getPartnum();
  uint8_t vr = cc1101.getVersion();
  Serial.printf("[CC1101] PARTNUM=0x%02X  VERSION=0x%02X", pn, vr);
  if ((pn == 0x00 || pn == 0xFF) && (vr == 0x00 || vr == 0xFF)) {
    Serial.println("  <- SPI error! Check wiring.");
    while (true) delay(1000);
  }
  Serial.println("  <- OK");

  setupRegisters();
  cc1101.spiStrobe(CC1101_SCAL);
  delay(2);

  uint8_t marc = cc1101.spiReadStatus(CC1101_MARCSTATE);
  Serial.printf("[CC1101] MARCSTATE=0x%02X %s\n", marc,
    marc == MARCSTATE_RX ? "-> RX OK" : "-> not in RX, calling setRx()...");
  if (marc != MARCSTATE_RX) { cc1101.setRx(); delay(2); }

  Serial.println("[CC1101] Waiting for CI=0x79 frames...");
#if PROMISCUOUS_MODE
  Serial.println("[ID] *** PROMISCUOUS_MODE active ***");
#endif
}

// =============================================================================
// RX LOOP
// =============================================================================
// GDO0 HIGH = sync word detected, frame arriving.
// Poll RXBYTES and read as bytes arrive. For CI=0x79 the frame is 58 bytes
// total (3 header + 55 payload) – well within the 64-byte FIFO.
// When GDO0 goes LOW the frame is complete.
// =============================================================================
static void resetRx()
{
  cc1101.spiStrobe(CC1101_SIDLE);
  cc1101.spiStrobe(CC1101_SFRX);
  cc1101.setRx();
  g_receiving    = false;
  g_rxBytesTotal = 0;
  g_lengthKnown  = false;
}

static void cc_loop()
{
  bool gdo0 = digitalRead(CC1101_GDO0);

  if (gdo0) {
    // Frame arriving
    if (!g_receiving) {
      g_receiving     = true;
      g_rxBytesTotal  = 0;
      g_expectedTotal = sizeof(g_payload);
      g_lengthKnown   = false;
    }

    // Read available bytes from FIFO
    uint8_t inFifo = cc1101.spiReadStatus(CC1101_RXBYTES) & 0x7F;
    while (inFifo > 0 && g_rxBytesTotal < sizeof(g_payload)) {
      g_payload[g_rxBytesTotal++] = cc1101.spiReadReg(CC1101_RXFIFO);
      inFifo--;
    }

    // Determine frame length from first 3 bytes: 0x54 0x3D L
    if (!g_lengthKnown && g_rxBytesTotal >= 3) {
      if (g_payload[0] == 0x54 && g_payload[1] == 0x3D) {
        g_expectedTotal = (uint16_t)g_payload[2] + 3;
        g_lengthKnown   = true;
        // Sanity check: CI=0x79 frames are always <= 80 bytes
        if (g_expectedTotal > sizeof(g_payload)) {
          Serial.printf("[RX] Frame too large (%u bytes) - discarding\n", g_expectedTotal);
          resetRx();
          return;
        }
      } else {
        // Spurious sync – not a wM-Bus C-mode frame
        Serial.println("[RX] Sync mismatch - discarding");
        resetRx();
        return;
      }
    }

  } else {
    // GDO0 LOW = frame complete (or aborted)
    if (!g_receiving) return;

    // Read any remaining bytes from FIFO
    uint8_t inFifo = cc1101.spiReadStatus(CC1101_RXBYTES) & 0x7F;
    while (inFifo > 0 && g_rxBytesTotal < sizeof(g_payload)) {
      g_payload[g_rxBytesTotal++] = cc1101.spiReadReg(CC1101_RXFIFO);
      inFifo--;
    }

    // Grab RSSI before strobe
    int16_t rssi = (int16_t)cc1101.getRSSI();

    if (!g_lengthKnown || g_rxBytesTotal < g_expectedTotal) {
      Serial.printf("[RX] Incomplete frame (%u/%u bytes) - discarding\n",
                    g_rxBytesTotal, g_expectedTotal);
      resetRx();
      return;
    }

    // Hand off to processing (C-field at [3], length = g_payload[2])
    uint8_t payLen = g_payload[2];
    resetRx();
    processPacket(&g_payload[3], payLen, rssi);
  }
}

// =============================================================================
// SETUP / LOOP
// =============================================================================
void setup()
{
  pinMode(PIN_LED, OUTPUT);
  digitalWrite(PIN_LED, HIGH);
  Serial.begin(115200);
  delay(300);
  Serial.println("\n===== WMBus_Diag (CI=0x79 only) =====");
  Serial.printf("[SYS] Meter-ID: %02X %02X %02X %02X\n",
                meterId[0], meterId[1], meterId[2], meterId[3]);
  cc_begin();
  digitalWrite(PIN_LED, LOW);
}

static unsigned long lastAlive = 0;

void loop()
{
  cc_loop();

  if (millis() - lastAlive >= 15000) {
    lastAlive = millis();
    uint8_t marc = cc1101.spiReadStatus(CC1101_MARCSTATE) & 0x1F;
    Serial.printf("[ALIVE] %lus  total=%lu  CI79=%lu  other=%lu  MARC=0x%02X%s\n",
      millis() / 1000,
      (unsigned long)g_pktTotal,
      (unsigned long)g_pktCI79,
      (unsigned long)g_pktOther,
      marc,
      marc == MARCSTATE_RX ? " (RX)" : " <- NOT in RX!");
    if (marc != MARCSTATE_RX) {
      Serial.println("[ALIVE] Restarting RX...");
      resetRx();
    }
  }
}
