# ESP_flowiq2200

Two Arduino sketches to read data from a Kamstrup FlowIQ 2200 water meter using a CC1101 radio module.

## Features
* **Big Sketch (Full + Compact Frames):**  
  Receives both 0x79 (Compact Frame) and 0x78 (Full Frame).  
  ⚠️ Note: This adds complexity due to handling Full Frames and mechanisms like GDO2 threshold burst detection.

* **Small Sketch (Recommended):**  
  Receives only 0x79 (Compact Frame).  
  This is the recommended approach as it is significantly simpler in structure.  
  The Compact Frame contains all relevant data and is transmitted every 16 seconds.

* **Data included in telegrams:**
  * **Total Consumption (Total Volume):** Current overall consumption in m³  
  * **Month-Start Consumption (Target Volume):** Consumption at the beginning of the current month in m³  
  * **Current Flow:** Instantaneous flow rate in L/h  
  * **Maximum Flow:** Maximum flow within the interval in L/h  
  * **Temperatures (Min/Max):** Minimum and maximum temperatures in °C  
  * **Status:** Status information of the meter  
  * **Date (Target Date):** Date of the month start (e.g., 2026-04-01)

* **Promiscuous Mode:**  
  Allows passive listening to all M-Bus messages in range to identify the **meter ID**.

* **CRC Check:**  
  Verifies the integrity of all received telegrams.

---

## Design Decision

The Compact Frame (CI=0x79) implementation was the main goal and took most of the effort.  
The Full Frame (CI=0x78) was added afterwards purely for comparison and validation — and frankly, it was a pain to get working reliably with the CC1101. FIFO limits, burst handling (GDO2), timing… all that complexity for basically no real benefit.

Some sources (e.g., https://github.com/erikxson/watermeter-flowiq2200) claim that Compact and Full Frames contain different data sets — especially for flow values (1-byte vs. 2-byte). That claim was the reason to dig deeper.

After analyzing both frame types from this specific meter, the result is simple:  
**all relevant data (Total Volume, Target Volume, Flow, Temperature, Status, etc.) is already present in the Compact Frame.**

The Full Frame doesn’t add anything useful here. It just confirms that the Compact Frame is complete.

**Conclusion:**  
Handling Full Frames is unnecessary overhead for this device.  
Compact Frames (CI=0x79) are simpler, more robust, and get the job done.



## Application-CI=0x79 (34 Bytes Plain) - Compact Frame


**Original Raw Payload:** `44 37 2C 38 19 65 53 3C 16 8D 20 2F F0 36 BC 20 E4 82 60 05 CC 49 F6 D4 4E 27 2A B1 1C 2E 29 D6 99 B4 4C 43 C3 78 BC 78 CC ED F6 A1 3A 09 0F 6B 78 FB 27 04`

**Decrypted Plain Payload:** `35 2A 79 05 09 61 78 00 00 00 00 E6 E4 00 00 5C 02 05 50 00 05 50 00 41 34 0B 0D EB 01 DD F3 00 00 0D`

<details>
<summary>Click here to expand the byte-by-byte table</summary>

| Byte Index | Value (Hex) | Interpretation |
| :--------- | :--------- | :------------- |
| 0          | ``35``     | Part of CRC Header (Byte 0 of 2) |
| 1          | ``2A``     | Part of CRC Header (Byte 1 of 2) |
| 2          | ``79``     | Application CI (0x79) |
| 3          | ``05``     | Part of Kamstrup Header (Byte 0 of 4) |
| 4          | ``09``     | Part of Kamstrup Header (Byte 1 of 4) |
| 5          | ``61``     | Part of Kamstrup Header (Byte 2 of 4) |
| 6          | ``78``     | Part of Kamstrup Header (Byte 3 of 4) |
| 7          | ``00``     | Part of Status Value (LSB, 00 00 00 00) |
| 8          | ``00``     | Part of Status Value (Byte 1, 00 00 00 00) |
| 9          | ``00``     | Part of Status Value (Byte 2, 00 00 00 00) |
| 10         | ``00``     | Part of Status Value (MSB, 00 00 00 00) -> **0x00000000 OK** |
| 11         | ``E6``     | Part of Target Volume (LSB, E6 E4 00 00) |
| 12         | ``E4``     | Part of Target Volume (Byte 1, E6 E4 00 00) |
| 13         | ``00``     | Part of Target Volume (Byte 2, E6 E4 00 00) |
| 14         | ``00``     | Part of Target Volume (MSB, E6 E4 00 00) -> **58.598 m³** |
| 15         | ``5C``     | Part of Max Flow (LSB, 5C 02) |
| 16         | ``02``     | Part of Max Flow (MSB, 5C 02) -> **604 L/h** |
| 17         | ``05``     | Part of Manufacturer Data (Byte 0 of 6) |
| 18         | ``50``     | Part of Manufacturer Data (Byte 1 of 6) |
| 19         | ``00``     | Part of Manufacturer Data (Byte 2 of 6) |
| 20         | ``05``     | Part of Manufacturer Data (Byte 3 of 6) |
| 21         | ``50``     | Part of Manufacturer Data (Byte 4 of 6) |
| 22         | ``00``     | Part of Manufacturer Data (Byte 5 of 6) |
| 23         | ``41``     | Part of Target Date (Byte 0 of 2) |
| 24         | ``34``     | Part of Target Date (Byte 1 of 2) -> **2026-04-01** |
| 25         | ``0B``     | Min Temperature -> **11 °C** |
| 26         | ``0D``     | Max Temperature -> **13 °C** |
| 27         | ``EB``     | Part of Current Flow (LSB, EB 01) |
| 28         | ``01``     | Part of Current Flow (MSB, EB 01) -> **491 L/h** |
| 29         | ``DD``     | Part of Total Volume (LSB, DD F3 00 00) |
| 30         | ``F3``     | Part of Total Volume (Byte 1, DD F3 00 00) |
| 31         | ``00``     | Part of Total Volume (Byte 2, DD F3 00 00) |
| 32         | ``00``     | Part of Total Volume (MSB, DD F3 00 00) -> **62.429 m³** |
| 33         | ``0D``     | End Value / Extra -> **13** |

</details>


## Application-CI=0x78 (55 Bytes Plain) - Full Frame


**Original Raw Payload:** `44 37 2C 38 19 65 53 3C 16 8D 20 30 F1 36 BC 20 AD 5B 75 1A 64 AF 2F 6E FC B2 CA B5 62 6E B9 97 B9 81 21 CD 42 F9 10 CB 70 7D AB BE 24 35 41 F6 16 B4 2C 03 6C 5D A9 89 95 E1 B7 56 97 42 DA AC 39 80 91 D1 FE EA A4 9B 1B`

**Decrypted Plain Payload:** `6F C4 78 04 FF 23 00 00 00 00 44 13 E6 E4 00 00 52 3B 5C 02 06 FF 1B 05 50 00 05 50 00 42 6C 41 34 61 67 0B 51 67 0D 02 3B EB 01 04 13 DD F3 00 00 81 01 E7 FF 0F 0D`

<details>
<summary>Click here to expand the byte-by-byte table</summary>

| Byte Index | Value (Hex) | Interpretation |
| :--------- | :--------- | :------------- |
| 0          | ``6F``     | Part of CRC Header (Byte 0 of 2) |
| 1          | ``C4``     | Part of CRC Header (Byte 1 of 2) |
| 2          | ``78``     | Application CI (0x78) |
| 3          | ``04``     | DIF_FF for Status Marker |
| 4          | ``FF``     | VIF_FF for Status Marker |
| 5          | ``23``     | Manufacturer Code for Status Marker |
| 6          | ``00``     | Part of Status Value (LSB, 00 00 00 00) |
| 7          | ``00``     | Part of Status Value (Byte 1, 00 00 00 00) |
| 8          | ``00``     | Part of Status Value (Byte 2, 00 00 00 00) |
| 9          | ``00``     | Part of Status Value (MSB, 00 00 00 00) -> **0x00000000 OK** |
| 10         | ``44``     | DIF for Total Volume |
| 11         | ``13``     | VIF for Total Volume |
| 12         | ``E6``     | Part of Target Volume (LSB, E6 E4 00 00) |
| 13         | ``E4``     | Part of Target Volume (Byte 1, E6 E4 00 00) |
| 14         | ``00``     | Part of Target Volume (Byte 2, E6 E4 00 00) |
| 15         | ``00``     | Part of Target Volume (MSB, E6 E4 00 00) -> **58.598 m³** |
| 16         | ``52``     | DIF for Max Flow |
| 17         | ``3B``     | VIF for Max Flow |
| 18         | ``5C``     | Part of Max Flow (LSB, 5C 02) |
| 19         | ``02``     | Part of Max Flow (MSB, 5C 02) -> **604 L/h** |
| 20         | ``06``     | DIF_FF for Manufacturer Marker |
| 21         | ``FF``     | VIF_FF for Manufacturer Marker |
| 22         | ``1B``     | Manufacturer Code for Manufacturer Marker |
| 23         | ``05``     | Part of Manufacturer Data (Byte 0 of 6) |
| 24         | ``50``     | Part of Manufacturer Data (Byte 1 of 6) |
| 25         | ``00``     | Part of Manufacturer Data (Byte 2 of 6) |
| 26         | ``05``     | Part of Manufacturer Data (Byte 3 of 6) |
| 27         | ``50``     | Part of Manufacturer Data (Byte 4 of 6) |
| 28         | ``00``     | Part of Manufacturer Data (Byte 5 of 6) |
| 29         | ``42``     | DIF for Target Date |
| 30         | ``6C``     | VIF for Target Date |
| 31         | ``41``     | Part of Target Date (Byte 0 of 2) |
| 32         | ``34``     | Part of Target Date (Byte 1 of 2) -> **2026-04-01** |
| 33         | ``61``     | DIF for Min Temperature |
| 34         | ``67``     | VIF for Min Temperature |
| 35         | ``0B``     | Min Temperature -> **11 °C** |
| 36         | ``51``     | DIF for Max Temperature |
| 37         | ``67``     | VIF for Max Temperature |
| 38         | ``0D``     | Max Temperature -> **13 °C** |
| 39         | ``02``     | DIF for Current Flow |
| 40         | ``3B``     | VIF for Current Flow |
| 41         | ``EB``     | Part of Current Flow (LSB, EB 01) |
| 42         | ``01``     | Part of Current Flow (MSB, EB 01) -> **491 L/h** |
| 43         | ``04``     | DIF for Total Volume |
| 44         | ``13``     | VIF for Total Volume |
| 45         | ``DD``     | Part of Total Volume (LSB, DD F3 00 00) |
| 46         | ``F3``     | Part of Total Volume (Byte 1, DD F3 00 00) |
| 47         | ``00``     | Part of Total Volume (Byte 2, DD F3 00 00) |
| 48         | ``00``     | Part of Total Volume (MSB, DD F3 00 00) -> **62.429 m³** |
| 49         | ``81``     | DIF_FF for Ext. Metadata |
| 50         | ``01``     | VIF_FF for Ext. Metadata |
| 51         | ``E7``     | Manufacturer Code (Part 1) |
| 52         | ``FF``     | Manufacturer Code (Part 2) |
| 53         | ``0F``     | VIF_FF (Continuation) for Ext. Metadata |
| 54         | ``0D``     | End Value / Extra -> **13** |

</details>

---
