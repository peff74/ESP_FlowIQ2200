### Telegramm #2: Application-CI=0x79 (Länge: 34 Bytes Plain)

Dieses Telegramm enthält keine Status- oder Volumenteile im Anfang, sondern beginnt direkt mit dem M-Bus-Block für das aktuelle Volumen.

| Byte 0   | Byte 1   | Byte 2       | Byte 3       | Byte 4       | Byte 5   | Byte 6             | Byte 7   |
| :------- | :------- | :----------- | :----------- | :----------- | :------- | :----------------- | :------- |
| `35 2A`  | `79`     | `05 09 61 78`| `DD F3 00 00`| `E6 E4 00 00`| `5C 02`  | `05 50 00 05 50 00`| `41 34`  |
| CRC (Crypto-Header) | Application CI | Kamstrup Header | Total Volume (DD F3 00 00) | Target Volume (E6 E4 00 00) | Max Flow (5C 02) | Hersteller-Daten (05 50 00 05 50 00) | Target Date (41 34) |

| Byte 8   | Byte 9   | Byte 10  | Byte 11      | Byte 12  | Byte 13  | Byte 14  | Byte 15  |
| :------- | :------- | :------- | :----------- | :------- | :------- | :------- | :------- |
| `0B`     | `0D`     | `EB 01`  | `DD F3 00 00`| `0D`     | -        | -        | -        |
| Min Temp (0B) | Max Temp (0D) | Current Flow (EB 01) | Total Volume redundant? (DD F3 00 00) | End-Wert (0D) | - | - | - |

#### Zusammenfassung (CI=0x79):

*   **Bytes 0-1:** `35 2A` (CRC / Crypto-Header)
*   **Byte 2:** `79` (Application CI)
*   **Bytes 3-6:** `05 09 61 78` (Kamstrup Header)
*   **Bytes 7-10:** `DD F3 00 00` -> DIF: `DD` (32-bit Integer, signed, Volumen), VIF: `F3` (Unit: 10⁻² m³, also Liter). Value: 0x0000F3DD = 62429 L = 62.429 m³ (Total Volume).
*   **Bytes 11-14:** `E6 E4 00 00` -> DIF: `E6` (32-bit Integer, signed, Volumen), VIF: `E4` (Unit: 10⁻¹ m³, also Liter). Value: 0x0000E4E6 = 58598 L = 58.598 m³ (Target Volume).
*   **Bytes 15-16:** `5C 02` -> DIF: `5C` (16-bit Integer, signed, Fluss), VIF: `02` (Unit: 10⁻¹ h). Value: 0x025C = 604 L/h (Max Flow).
*   **Bytes 17-22:** `05 50 00 05 50 00` -> DIF: `05` (6-Byte Hersteller), VIF: `50` (Hersteller spezifisch). Value: `50 00 05 50 00`.
*   **Bytes 23-24:** `41 34` -> **Zuordnung:** Target Date (41 34). Interpretation laut Log: 2026-04-01.
*   **Byte 25:** `0B` -> DIF: `0B` (8-bit Integer, signed, Temperatur), VIF: `0B` (Unit: °C). Value: 0x0B = 11 °C (Min Temperature).
*   **Byte 26:** `0D` -> DIF: `0D` (8-bit Integer, signed, Temperatur), VIF: `0D` (Unit: °C). Value: 0x0D = 13 °C (Max Temperature).
*   **Bytes 27-28:** `EB 01` -> DIF: `EB` (16-bit Integer, signed, Fluss), VIF: `01` (Unit: 10⁻⁰ h). Value: 0x01EB = 491 L/h (Current Flow).
*   **Bytes 29-32:** `DD F3 00 00` -> Siehe oben (Redundanter Total Volume Eintrag oder Fehler in der Interpretation? Log zeigt diesen Eintrag nicht separat an). **Zuordnung:** (Wahrscheinlich redundant oder Teil nächster Block, falls vorhanden).
*   **Byte 33:** `0D` -> **Zuordnung:** End-Wert / Extra (0D).



### Telegramm #3: Application-CI=0x78 (Länge: 55 Bytes Plain)

Dieses Telegramm beginnt mit Status- und Volumenteilen, gefolgt von anderen Messwerten.

| Byte 0   | Byte 1   | Byte 2    | Byte 3       | Byte 4       | Byte 5       | Byte 6   | Byte 7   |
| :------- | :------- | :-------- | :----------- | :----------- | :----------- | :------- | :------- |
| `6F C4`  | `78`     | `04 FF 23`| `00 00 00 00`| `44 13`      | `E6 E4 00 00`| `52 3B`  | `5C 02`  |
| CRC (Crypto-Header) | Application CI | DIF/VIF Marker Status | Status Value | DIF/VIF Total Vol | Total Volume Value | DIF/VIF Max Flow | Max Flow Value |

| Byte 8       | Byte 9                 | Byte 10  | Byte 11  | Byte 12  | Byte 13  | Byte 14  | Byte 15  |
| :----------- | :--------------------- | :------- | :------- | :------- | :------- | :------- | :------- |
| `06 FF 1B`   | `05 50 00 05 50 00`    | `42 6C`  | `41 34`  | `61 67`  | `0B`     | `51 67`  | `0D`     |
| DIF/VIF Marker Herst. | Hersteller Value | DIF/VIF Target Date | Target Date Value | DIF/VIF Min Temp | Min Temp Value | DIF/VIF Max Temp | Max Temp Value |

| Byte 16  | Byte 17  | Byte 18  | Byte 19      | Byte 20          | Byte 21  | Byte 22  | Byte 23  |
| :------- | :------- | :------- | :----------- | :--------------- | :------- | :------- | :------- |
| `02 3B`  | `EB 01`  | `04 13`  | `DD F3 00 00`| `81 01 E7 FF 0F` | `0D`     | -        | -        |
| DIF/VIF Current Flow | Current Flow Value | DIF/VIF Total Vol | Total Volume Value | DIF/VIF Ext Meta | End Value | - | - |

#### Zusammenfassung (CI=0x78):

*   **Bytes 0-1:** `6F C4` (CRC / Crypto-Header)
*   **Byte 2:** `78` (Application CI)
*   **Bytes 3-5:** `04 FF 23` -> DIF_FF=04, VIF_FF=23, MAN=FF (Besagt: Es folgt ein 8-bit unsigned Wert vom Hersteller). DATA: `00 00 00 00` (4 Bytes). Laut Tabelle ist dies ein Marker für den nächsten Block.
*   **Bytes 6-9:** `00 00 00 00` -> Interpretiert als Wert zum vorherigen Marker `04 FF 23`. **Zuordnung:** Status / Error-Flags = `00 00 00 00`
*   **Bytes 10-13:** `44 13` -> DIF: `44` (32-bit Integer, signed), VIF: `13` (Hersteller spezifisch). DATA: `E6 E4 00 00`. **Zuordnung:** Target Volume = `E6 E4 00 00` (58.598 m³)
*   **Bytes 14-15:** `52 3B` -> DIF: `52` (16-bit Integer, signed), VIF: `3B` (Hersteller spezifisch). DATA: `5C 02`. **Zuordnung:** Max Flow = `5C 02` (604 L/h)
*   **Bytes 16-22:** `06 FF 1B` -> DIF_FF=06, VIF_FF=1B, MAN=FF (Besagt: Es folgt ein 16-bit unsigned Wert vom Hersteller). DATA: `05 50 00 05 50 00` (6 Bytes). Laut Tabelle ist dies ein Marker.
*   **Bytes 23-28:** `05 50 00 05 50 00` -> Interpretiert als Wert zum vorherigen Marker `06 FF 1B`. **Zuordnung:** Hersteller-Daten = `05 50 00 05 50 00`
*   **Bytes 29-30:** `42 6C` -> DIF: `42` (16-bit Integer, unsigned), VIF: `6C` (Datum Typ F: Day.Month). DATA: `41 34`. **Zuordnung:** Target Date = `41 34` (2026-04-01) (Interpretation laut Log)
*   **Bytes 31-32:** `61 67` -> DIF: `61` (8-bit Integer, signed), VIF: `67` (Temperatur). DATA: `0B`. **Zuordnung:** Min Temperature = `0B` (11 °C)
*   **Bytes 33-34:** `51 67` -> DIF: `51` (8-bit Integer, signed), VIF: `67` (Temperatur). DATA: `0D`. **Zuordnung:** Max Temperature = `0D` (13 °C)
*   **Bytes 35-36:** `02 3B` -> DIF: `02` (16-bit Integer, signed), VIF: `3B` (Fluss). DATA: `EB 01`. **Zuordnung:** Current Flow = `EB 01` (491 L/h)
*   **Bytes 37-40:** `04 13` -> DIF: `04` (32-bit Integer, signed), VIF: `13` (Volumen). DATA: `DD F3 00 00`. **Zuordnung:** Total Volume = `DD F3 00 00` (62.429 m³)
*   **Bytes 41-45:** `81 01 E7 FF 0F` -> DIF_FF=81, VIF_FF=0F, MAN=E7 FF (Besagt: Es folgt ein variabler Datentyp vom Hersteller). DATA: `0D`. Laut Tabelle ist dies ein Marker.
*   **Byte 46:** `0D` -> Interpretiert als Wert zum vorherigen Block. **Zuordnung:** End-Wert / Extra (0D) (Wahrscheinlich der Wert zum vorherigen Block `81 01 E7 FF 0F`)
