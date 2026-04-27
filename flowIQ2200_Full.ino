/*
  WMBus_Diag - Diagnostic sketch (no WiFi, no MQTT)
  Receives wM-Bus C-Mode telegrams, checks Meter-ID,
  decrypts and displays CI=0x79 (Compact) and CI=0x78 (Full) frames.
  Uses GDO2 FIFO threshold draining for frames > 64 bytes.

  Libraries: Crypto (rweather), CC1101_ESP_Arduino
  Board: ESP32 Dev Module
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
#define CC1101_GDO0  27   // HIGH on sync word detected
#define CC1101_GDO2  26   // HIGH when RX FIFO >= threshold
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
#define READ_BURST              0xC0
#define CC1101_STATUS_REGISTER  READ_BURST
#define CC1101_RXFIFO    0x3F
#define CC1101_RXBYTES   0x3B
#define CC1101_SCAL      0x33
#define CC1101_SIDLE     0x36
#define CC1101_SFRX      0x3A
#define CC1101_MARCSTATE 0x35
#define MARCSTATE_RX     0x0D

// =============================================================================
// TYPES – before all functions (Arduino IDE auto-prototype safety)
// =============================================================================

// DIF data field length table (bits[3:0] of DIF byte)
// -1 = variable (next byte = length), 0 = no data
static const int8_t kDifDataLen[16] = {
  0, 1, 2, 3, 4, 4, 6, 8, 0, 1, 2, 3, 4, -1, 6, 0
};

struct CI78Fields {
  bool     hasTotal;    uint32_t totalL;
  bool     hasTarget;   uint32_t targetL;
  bool     hasDate;     uint16_t tYear; uint8_t tMonth; uint8_t tDay;
  bool     hasFlow;     uint16_t flowLph;
  bool     hasMaxFlow;  uint16_t maxFlowLph;
  bool     hasMinFlow;  uint16_t minFlowLph;
  bool     hasStatus;   uint32_t status;
  bool     hasFlowTemp; int8_t   flowTempC;
  bool     hasMinTemp;  int8_t   minTempC;
  bool     hasMaxTemp;  int8_t   maxTempC;
};

// =============================================================================
// GLOBALS
// =============================================================================
CC1101 cc1101(CC1101_SCK, CC1101_MISO, CC1101_MOSI, CC1101_CSN, CC1101_GDO0, -1);

static uint8_t  g_payload[300];
static uint16_t g_rxBytesTotal  = 0;
static uint16_t g_expectedTotal = 0;
static bool     g_lengthKnown   = false;
static bool     g_receiving     = false;

static uint32_t g_pktTotal = 0;
static uint32_t g_pktCI79  = 0;
static uint32_t g_pktCI78  = 0;
static uint32_t g_pktOther = 0;

CTR<AESSmall128> aes128;
static uint8_t g_plain[255];
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
// Verified empirically: plain[0-1] = CRC(plain[2..end]) for both CI=0x79 and CI=0x78
static uint16_t crc16_en13757(const uint8_t* data, size_t len)
{
  uint16_t crc = 0x0000;
  for (size_t i = 0; i < len; i++) {
    crc ^= (uint16_t)(data[i] << 8);
    for (uint8_t bit = 0; bit < 8; bit++) {
      crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x3D65)
                           : (uint16_t)(crc << 1);
    }
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
  if (plainLen == 0 || plainLen > 200) { Serial.println("[DEC] Invalid length"); return false; }

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
// CI=0x78 DIF/VIF PARSER
// =============================================================================
static void parseCI78Records(const uint8_t* data, uint8_t len, CI78Fields& f)
{
  memset(&f, 0, sizeof(f));
  if (!data || len < 3) return;

  size_t pos = 3;   // skip CRC[0-1] and CI[2]
  int    maxRec = 20;

  while (pos < len && maxRec-- > 0) {
    if (pos >= len) break;
    uint8_t dif = data[pos++];

    // End / manufacturer specific markers
    if (dif == 0x0F || dif == 0x1F || dif == 0x2F) { if (pos < len) pos++; break; }
    if ((dif & 0x0F) == 0x00) break;

    uint8_t difFunc = (dif >> 4) & 0x03;   // 00=inst 01=max 02=min
    bool    hasDife = (dif & 0x80) != 0;
    uint8_t storage = (dif >> 6) & 0x01;

    while (hasDife && pos < len) {
      uint8_t dife = data[pos++];
      storage |= (uint8_t)((dife & 0x0F) << 1);
      hasDife = (dife & 0x80) != 0;
    }
    if (pos >= len) break;

    uint8_t vif     = data[pos++];
    bool    hasVife = (vif & 0x80) != 0;
    uint8_t vif7    = vif & 0x7F;
    uint8_t vife    = 0;
    while (hasVife && pos < len) {
      vife    = data[pos] & 0x7F;
      hasVife = (data[pos++] & 0x80) != 0;
    }
    if (pos >= len) break;

    int8_t dlen_s = kDifDataLen[dif & 0x0F];
    if (dlen_s < 0) {
      if (pos >= len) break;
      pos += (uint8_t)data[pos] + 1;
      continue;
    }
    uint8_t dlen = (uint8_t)dlen_s;
    if (pos + dlen > len) break;

    const uint8_t* dp = &data[pos];
    pos += dlen;

    uint32_t val32 = 0;
    for (uint8_t i = 0; i < dlen && i < 4; i++)
      val32 |= ((uint32_t)dp[i] << (8 * i));

    // Status: DIF=0x04, VIF=0xFF+VIFE=0x23
    if ((dif & 0x0F) == 4 && vif7 == 0x7F && vife == 0x23) {
      f.hasStatus = true; f.status = val32; continue;
    }
    // Volume liters: VIF=0x13, 4 bytes
    if (vif7 == 0x13 && dlen == 4) {
      if (storage == 0 && difFunc == 0) { f.hasTotal  = true; f.totalL  = val32; continue; }
      if (storage >= 1 && difFunc == 0) { f.hasTarget = true; f.targetL = val32; continue; }
    }
    // Volume flow L/h: VIF=0x3B, 2 bytes
    if (vif7 == 0x3B && dlen == 2) {
      uint16_t v = (uint16_t)val32;
      if (difFunc == 0) { f.hasFlow    = true; f.flowLph    = v; continue; }
      if (difFunc == 1) { f.hasMaxFlow = true; f.maxFlowLph = v; continue; }
      if (difFunc == 2) { f.hasMinFlow = true; f.minFlowLph = v; continue; }
    }
    // Date type G: VIF=0x6C, 2 bytes
    if (vif7 == 0x6C && dlen == 2) {
      f.hasDate = true;
      f.tDay    = dp[0] & 0x1F;
      f.tMonth  = dp[1] & 0x0F;
      f.tYear   = (uint16_t)(2000 + (((dp[1] >> 4) << 3) | (dp[0] >> 5)));
      continue;
    }
    // Flow temperature: VIF=0x5B, 1 byte signed
    if (vif7 == 0x5B && dlen == 1) {
      f.hasFlowTemp = true; f.flowTempC = (int8_t)dp[0]; continue;
    }
    // External temperature: VIF=0x67, 1 byte signed
    if (vif7 == 0x67 && dlen == 1) {
      if (difFunc == 2) { f.hasMinTemp = true; f.minTempC = (int8_t)dp[0]; continue; }
      if (difFunc == 1) { f.hasMaxTemp = true; f.maxTempC = (int8_t)dp[0]; continue; }
      f.hasMinTemp = true; f.minTempC = (int8_t)dp[0]; continue;
    }
    // unknown record: pos already advanced past data
  }
}

static void printCI78(const CI78Fields& f)
{
  const char* ss = "OK";
  if (f.hasStatus) {
    if      (f.status & 0x01) ss = "DRY";
    else if (f.status & 0x02) ss = "REVERSE";
    else if (f.status & 0x04) ss = "LEAK";
    else if (f.status & 0x08) ss = "BURST";
    else if (f.status != 0)   ss = "ERROR";
  }

  if (f.hasTotal)
    Serial.printf("[VAL] total_m3     = %u.%03u m3\n",   f.totalL  / 1000, f.totalL  % 1000);
  else
    Serial.println("[VAL] total_m3     = (not in frame)");

  if (f.hasTarget)
    Serial.printf("[VAL] target_m3    = %u.%03u m3\n",   f.targetL / 1000, f.targetL % 1000);
  if (f.hasDate)
    Serial.printf("[VAL] target_date  = %04u-%02u-%02u\n", f.tYear, f.tMonth, f.tDay);
  if (f.hasFlow)
    Serial.printf("[VAL] flow_now     = %u L/h  (%.3f m3/h)\n",
                  f.flowLph, f.flowLph / 1000.0f);
  if (f.hasMaxFlow)
    Serial.printf("[VAL] max_flow     = %u L/h  (%.3f m3/h)\n",
                  f.maxFlowLph, f.maxFlowLph / 1000.0f);
  if (f.hasMinFlow)
    Serial.printf("[VAL] min_flow     = %u L/h  (%.3f m3/h)\n",
                  f.minFlowLph, f.minFlowLph / 1000.0f);
  if (f.hasFlowTemp)
    Serial.printf("[VAL] flow_temp    = %d degC\n", (int)f.flowTempC);
  if (f.hasMinTemp)
    Serial.printf("[VAL] min_ext_temp = %d degC\n", (int)f.minTempC);
  if (f.hasMaxTemp)
    Serial.printf("[VAL] max_ext_temp = %d degC\n", (int)f.maxTempC);
  if (f.hasStatus)
    Serial.printf("[VAL] status       = 0x%08X  %s\n", (unsigned)f.status, ss);
}

// =============================================================================
// PACKET PROCESSING
// =============================================================================
static void processPacket(const uint8_t* payload, uint8_t payLen, int16_t rssi)
{
  g_pktTotal++;
  Serial.printf("\n====== Packet #%lu  RSSI=%d dBm ======\n",
                (unsigned long)g_pktTotal, (int)rssi);

  // 1. RAW output – always first, before any processing
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

  // 4. CRC check – same formula for both CI=0x79 and CI=0x78
  uint16_t readCrc = (uint16_t)g_plain[0] | ((uint16_t)g_plain[1] << 8);
  uint16_t calcCrc = crc16_en13757(&g_plain[2], plainLen - 2);
  bool     crcOk   = (calcCrc == readCrc);
  Serial.printf("[CRC] read=0x%04X  calc=0x%04X  %s\n",
                readCrc, calcCrc, crcOk ? "OK" : "FAIL - corrupt or wrong key!");
  if (!crcOk) return;

  // 5. Parse
  if (appCI == 0x79) {
    // Compact Frame – fixed offsets verified against wmbusmeters
    g_pktCI79++;
    if (plainLen < 33) { Serial.println("[CI] Compact Frame too short!"); return; }
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

  } else if (appCI == 0x78) {
    // Full Frame – sequential DIF/VIF parser (record order varies per meter)
    g_pktCI78++;
    Serial.println("[CI]  Full Frame (0x78) - FlowIQ 2200");
    CI78Fields f;
    parseCI78Records(g_plain, plainLen, f);
    printCI78(f);

  } else if (appCI == 0x53) {
    g_pktOther++;
    Serial.println("[CI]  Long Transport Layer (0x53)");

  } else {
    g_pktOther++;
    Serial.printf("[CI]  Unknown Application-CI=0x%02X\n", appCI);
  }
}

// =============================================================================
// CC1101 SETUP
// =============================================================================
static void setupRegisters()
{
  cc1101.spiWriteReg(0x00, 0x00);  // IOCFG2: HIGH when RX FIFO >= threshold
  cc1101.spiWriteReg(0x02, 0x06);  // IOCFG0: HIGH on sync word
  cc1101.spiWriteReg(0x03, 0x07);  // FIFOTHR: RX threshold = 32 bytes
  cc1101.spiWriteReg(0x06, 0x30);  // PKTLEN
  cc1101.spiWriteReg(0x07, 0x00);  // PKTCTRL1
  cc1101.spiWriteReg(0x08, 0x02);  // PKTCTRL0: infinite length
  cc1101.spiWriteReg(0x04, 0x54);  // SYNC1
  cc1101.spiWriteReg(0x05, 0x3D);  // SYNC0
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
  pinMode(CC1101_GDO2, INPUT);

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

  Serial.println("[CC1101] Waiting for packets (FIFO Draining Mode)...");
#if PROMISCUOUS_MODE
  Serial.println("[ID] *** PROMISCUOUS_MODE active ***");
#endif
}

// =============================================================================
// RX LOOP - GDO2 threshold burst draining
// =============================================================================
static void cc_loop()
{
  bool gdo0 = digitalRead(CC1101_GDO0);
  bool gdo2 = digitalRead(CC1101_GDO2);

  if (gdo0) {
    // Sync word active – frame is arriving
    if (!g_receiving) {
      g_receiving     = true;
      g_rxBytesTotal  = 0;
      g_expectedTotal = 255;
      g_lengthKnown   = false;
    }

    // GDO2 HIGH: FIFO >= 32 bytes – burst-read chunk
    if (gdo2) {
      uint8_t chunk[32];
      cc1101.spiReadRegBurst(CC1101_RXFIFO, chunk, 32);
      for (uint8_t i = 0; i < 32; i++) {
        if (g_rxBytesTotal < sizeof(g_payload))
          g_payload[g_rxBytesTotal++] = chunk[i];
      }
    }

    // Once we have first 3 bytes: 0x54 0x3D L – determine total length
    if (!g_lengthKnown && g_rxBytesTotal >= 3) {
      if (g_payload[0] == 0x54 && g_payload[1] == 0x3D) {
        g_expectedTotal = (uint16_t)g_payload[2] + 3;  // sync(2) + L-byte(1) + payload(L)
        g_lengthKnown   = true;
      } else {
        // Spurious match – abort
        cc1101.spiStrobe(CC1101_SIDLE);
        cc1101.spiStrobe(CC1101_SFRX);
        cc1101.setRx();
        g_receiving = false;
        return;
      }
    }

    // Poll for tail bytes when < 32 remain (GDO2 won't fire again)
    if (g_lengthKnown) {
      int16_t missing = (int16_t)g_expectedTotal - (int16_t)g_rxBytesTotal;
      if (missing > 0 && missing < 32) {
        uint8_t inFifo = cc1101.spiReadStatus(CC1101_RXBYTES) & 0x7F;
        if (inFifo >= (uint8_t)missing) {
          uint8_t chunk[32];
          cc1101.spiReadRegBurst(CC1101_RXFIFO, chunk, (uint8_t)missing);
          for (int16_t i = 0; i < missing; i++) {
            if (g_rxBytesTotal < sizeof(g_payload))
              g_payload[g_rxBytesTotal++] = chunk[i];
          }
        }
      }
    }

    // All bytes collected – process frame
    if (g_lengthKnown && g_rxBytesTotal >= g_expectedTotal) {
      int16_t rssi = (int16_t)cc1101.getRSSI();
      cc1101.spiStrobe(CC1101_SIDLE);
      cc1101.spiStrobe(CC1101_SFRX);
      cc1101.setRx();
      g_receiving = false;
      // C-field starts at g_payload[3], payload length = g_payload[2]
      processPacket(&g_payload[3], g_payload[2], rssi);
    }

  } else {
    // GDO0 LOW
    if (g_receiving) {
      cc1101.spiStrobe(CC1101_SIDLE);
      cc1101.spiStrobe(CC1101_SFRX);
      cc1101.setRx();
      g_receiving = false;
      Serial.println("[RX] Frame aborted (GDO0 went LOW before complete)");
    } else {
      // Recover from RXFIFO_OVERFLOW
      if ((cc1101.spiReadStatus(CC1101_MARCSTATE) & 0x1F) == 0x11) {
        cc1101.spiStrobe(CC1101_SIDLE);
        cc1101.spiStrobe(CC1101_SFRX);
        cc1101.setRx();
      }
    }
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
  Serial.println("\n===== WMBus_Diag =====");
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
    Serial.printf("[ALIVE] %lus  total=%lu  CI79=%lu  CI78=%lu  other=%lu  MARC=0x%02X%s\n",
      millis() / 1000,
      (unsigned long)g_pktTotal,
      (unsigned long)g_pktCI79,
      (unsigned long)g_pktCI78,
      (unsigned long)g_pktOther,
      marc,
      marc == MARCSTATE_RX ? " (RX)" : " <- NOT in RX!");
    if (marc != MARCSTATE_RX) {
      Serial.println("[ALIVE] Restarting RX...");
      cc1101.spiStrobe(CC1101_SIDLE);
      cc1101.spiStrobe(CC1101_SFRX);
      cc1101.setRx();
    }
  }
}
