### Telegramm #2: Application-CI=0x79 (Länge: 34 Bytes Plain)

Dieses Telegramm enthält keine Status- oder Volumenteile im Anfang, sondern beginnt direkt mit dem M-Bus-Block für das aktuelle Volumen.

**Original Raw Payload:** `44 37 2C 38 19 65 53 3C 16 8D 20 2F F0 36 BC 20 E4 82 60 05 CC 49 F6 D4 4E 27 2A B1 1C 2E 29 D6 99 B4 4C 43 C3 78 BC 78 CC ED F6 A1 3A 09 0F 6B 78 FB 27 04`

**Decrypted Plain Payload:** `35 2A 79 05 09 61 78 00 00 00 00 E6 E4 00 00 5C 02 05 50 00 05 50 00 41 34 0B 0D EB 01 DD F3 00 00 0D`

| Byte 0   | Byte 1   | Byte 2       | Byte 3       | Byte 4       | Byte 5   | Byte 6             | Byte 7   |
| :------- | :------- | :----------- | :----------- | :----------- | :------- | :----------------- | :------- |
| ``35 2A``| ``79``   | ``05 09 61 78`` | ``DD F3 00 00`` (62.429 m³) | ``E6 E4 00 00`` (58.598 m³) | ``5C 02`` (604 L/h) | ``05 50 00 05 50 00`` | ``41 34`` (2026-04-01) |
| **CRC (Crypto-Header)** | **Application CI** | **Kamstrup Header** | **Total Volume** | **Target Volume** | **Max Flow** | **Hersteller-Daten** | **Target Date** |

| Byte 8   | Byte 9   | Byte 10  | Byte 11      | Byte 12  | Byte 13  | Byte 14  | Byte 15  |
| :------- | :------- | :------- | :----------- | :------- | :------- | :------- | :------- |
| ``0B`` (11 °C) | ``0D`` (13 °C) | ``EB 01`` (491 L/h) | ``DD F3 00 00`` (62.429 m³, redundant?) | ``0D`` | -        | -        | -        |
| **Min Temp** | **Max Temp** | **Current Flow** | *Total Volume redundant?* | **End-Wert** | - | - | - |

#### Zusammenfassung (CI=0x79):

*   **Bytes 0-1:** ``35 2A`` (CRC / Crypto-Header)
*   **Byte 2:** ``79`` (Application CI)
*   **Bytes 3-6:** ``05 09 61 78`` (Kamstrup Header)
*   **Bytes 7-10:** ``DD F3 00 00`` -> DIF: `DD`, VIF: `F3`. Value: 62429 L = **62.429 m³** (Total Volume).
*   **Bytes 11-14:** ``E6 E4 00 00`` -> DIF: `E6`, VIF: `E4`. Value: 58598 L = **58.598 m³** (Target Volume).
*   **Bytes 15-16:** ``5C 02`` -> DIF: `5C`, VIF: `02`. Value: **604 L/h** (Max Flow).
*   **Bytes 17-22:** ``05 50 00 05 50 00`` -> DIF: `05`, VIF: `50`. Value: `50 00 05 50 00` (Herstellerdaten).
*   **Bytes 23-24:** ``41 34`` -> **Zuordnung:** Target Date (41 34). Interpretation laut Log: **2026-04-01**.
*   **Byte 25:** ``0B`` -> DIF: `0B`, VIF: `0B`. Value: **11 °C** (Min Temperature).
*   **Byte 26:** ``0D`` -> DIF: `0D`, VIF: `0D`. Value: **13 °C** (Max Temperature).
*   **Bytes 27-28:** ``EB 01`` -> DIF: `EB`, VIF: `01`. Value: **491 L/h** (Current Flow).
*   **Bytes 29-32:** ``DD F3 00 00`` -> Siehe oben (Redundanter Total Volume Eintrag oder Fehler in der Interpretation? Log zeigt diesen Eintrag nicht separat an). **Zuordnung:** (Wahrscheinlich redundant oder Teil nächster Block, falls vorhanden).
*   **Byte 33:** ``0D`` -> **Zuordnung:** End-Wert / Extra (0D).



### Telegramm #3: Application-CI=0x78 (Länge: 55 Bytes Plain)

Dieses Telegramm beginnt mit Status- und Volumenteilen, gefolgt von anderen Messwerten.

**Original Raw Payload:** `44 37 2C 38 19 65 53 3C 16 8D 20 30 F1 36 BC 20 AD 5B 75 1A 64 AF 2F 6E FC B2 CA B5 62 6E B9 97 B9 81 21 CD 42 F9 10 CB 70 7D AB BE 24 35 41 F6 16 B4 2C 03 6C 5D A9 89 95 E1 B7 56 97 42 DA AC 39 80 91 D1 FE EA A4 9B 1B`

**Decrypted Plain Payload:** `6F C4 78 04 FF 23 00 00 00 00 44 13 E6 E4 00 00 52 3B 5C 02 06 FF 1B 05 50 00 05 50 00 42 6C 41 34 61 67 0B 51 67 0D 02 3B EB 01 04 13 DD F3 00 00 81 01 E7 FF 0F 0D`

| Byte 0   | Byte 1   | Byte 2    | Byte 3       | Byte 4       | Byte 5       | Byte 6   | Byte 7   |
| :------- | :------- | :-------- | :----------- | :----------- | :----------- | :------- | :------- |
| ``6F C4``| ``78``   | ``04 FF 23`` | ``00 00 00 00`` (0x00000000 OK) | ``44 13`` | ``E6 E4 00 00`` (58.598 m³) | ``52 3B`` | ``5C 02`` (604 L/h) |
| **CRC (Crypto-Header)** | **Application CI** | **DIF/VIF Marker Status** | **Status Value** | **DIF/VIF Total Vol** | **Total Volume Value** | **DIF/VIF Max Flow** | **Max Flow Value** |

| Byte 8       | Byte 9                 | Byte 10  | Byte 11  | Byte 12  | Byte 13  | Byte 14  | Byte 15  |
| :----------- | :--------------------- | :------- | :------- | :------- | :------- | :------- | :------- |
| ``06 FF 1B`` | ``05 50 00 05 50 00`` | ``42 6C``| ``41 34`` (2026-04-01) | ``61 67`` | ``0B`` (11 °C) | ``51 67`` | ``0D`` (13 °C) |
| **DIF/VIF Marker Herst.** | **Hersteller Value** | **DIF/VIF Target Date** | **Target Date Value** | **DIF/VIF Min Temp** | **Min Temp Value** | **DIF/VIF Max Temp** | **Max Temp Value** |

| Byte 16  | Byte 17  | Byte 18  | Byte 19      | Byte 20          | Byte 21  | Byte 22  | Byte 23  |
| :------- | :------- | :------- | :----------- | :--------------- | :------- | :------- | :------- |
| ``02 3B`` | ``EB 01`` (491 L/h) | ``04 13`` | ``DD F3 00 00`` (62.429 m³) | ``81 01 E7 FF 0F`` | ``0D`` | -        | -        |
| **DIF/VIF Current Flow** | **Current Flow Value** | **DIF/VIF Total Vol** | **Total Volume Value** | **DIF/VIF Ext Meta** | **End Value** | - | - |

#### Zusammenfassung (CI=0x78):

*   **Bytes 0-1:** ``6F C4`` (CRC / Crypto-Header)
*   **Byte 2:** ``78`` (Application CI)
*   **Bytes 3-5:** ``04 FF 23`` -> DIF_FF=``04``, VIF_FF=``23``, MAN=``FF`` (Besagt: Es folgt ein 8-bit unsigned Wert vom Hersteller). DATA: ``00 00 00 00`` (4 Bytes). Laut Tabelle ist dies ein Marker für den nächsten Block.
*   **Bytes 6-9:** ``00 00 00 00`` -> Interpretiert als Wert zum vorherigen Marker `04 FF 23`. **Zuordnung:** Status / Error-Flags = **0x00000000 OK**
*   **Bytes 10-13:** ``44 13`` -> DIF: `44`, VIF: `13`. DATA: ``E6 E4 00 00``. Value: 58598 L = **58.598 m³** (Target Volume).
*   **Bytes 14-15:** ``52 3B`` -> DIF: `52`, VIF: `3B`. DATA: ``5C 02``. Value: **604 L/h** (Max Flow).
*   **Bytes 16-22:** ``06 FF 1B`` -> DIF_FF=``06``, VIF_FF=``1B``, MAN=``FF`` (Besagt: Es folgt ein 16-bit unsigned Wert vom Hersteller). DATA: ``05 50 00 05 50 00`` (6 Bytes). Laut Tabelle ist dies ein Marker.
*   **Bytes 23-28:** ``05 50 00 05 50 00`` -> Interpretiert als Wert zum vorherigen Marker `06 FF 1B`. **Zuordnung:** Hersteller-Daten = `05 50 00 05 50 00`
*   **Bytes 29-30:** ``42 6C`` -> DIF: `42`, VIF: `6C`. DATA: ``41 34``. Value: **2026-04-01** (Target Date).
*   **Bytes 31-32:** ``61 67`` -> DIF: `61`, VIF: `67`. DATA: ``0B``. Value: **11 °C** (Min Temperature).
*   **Bytes 33-34:** ``51 67`` -> DIF: `51`, VIF: `67`. DATA: ``0D``. Value: **13 °C** (Max Temperature).
*   **Bytes 35-36:** ``02 3B`` -> DIF: `02`, VIF: `3B`. DATA: ``EB 01``. Value: **491 L/h** (Current Flow).
*   **Bytes 37-40:** ``04 13`` -> DIF: `04`, VIF: `13`. DATA: ``DD F3 00 00``. Value: 62429 L = **62.429 m³** (Total Volume).
*   **Bytes 41-45:** ``81 01 E7 FF 0F`` -> DIF_FF=``81``, VIF_FF=``0F``, MAN=``E7 FF`` (Besagt: Es folgt ein variabler Datentyp vom Hersteller). DATA: ``0D``. Laut Tabelle ist dies ein Marker.
*   **Byte 46:** ``0D`` -> Interpretiert als Wert zum vorherigen Block. **Zuordnung:** End-Wert / Extra (0D) (Wahrscheinlich der Wert zum vorherigen Block `81 01 E7 FF 0F`)
