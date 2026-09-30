# CS2 Server Lagger 原理分析

> 本文為既有程式碼（`crash.cpp`）的靜態分析紀錄。

---

## 1. 一句話總結

從**經過認證的遊戲客戶端內部**，沿著遊戲自己的加密網路通道（SDR），每個 server tick 灌進大量精心構造的語音訊息，利用「客戶端生成成本趨近於零、伺服器解析成本指數放大」的不對稱性，耗盡伺服器每 tick 的網路處理預算與上鏈頻寬，導致全服卡頓。

---

## 2. 攻擊面選擇：語音訊息路徑

攻擊面選在 CS2 的**遊戲語音（voice data）protobuf 路徑**，原因有三：

1. **訊息被伺服器強制處理** — 語音訊息進入伺服器後必然走 protobuf 完整解析，無法提前丟棄
2. **語音是伺服器中繼的** — 解析後還有路由/轉發成本，成本被放大到全服
3. **repeated field 的解析成本可控放大** — 一個欄位宣告就能產生上萬次條目迭代

---

## 3. Payload 構造（`make_voice_payload`）

程式手刻了一個等價 `CMsgVoiceData` 的 protobuf 訊息。10-byte prefix + 後綴的位元組級解讀：

```
0A                    外層 field 1 (LEN) → voice_data 巢狀訊息
<len varint>          內層長度 = 2 + 2 + 3 + N
    08 02             內層 field 1 (VARINT) = 2     ← 格式/版本
    12 00             內層 field 2 (LEN, 長度 0)     ← 真正的音訊資料：空的
    42 <len varint>   內層 field 8 (LEN)            ← payload_offsets（repeated）
    [N 個 0x00]       ← N = 1475 或 16320
11 <xuid × 8 LE>      外層 field 2 (fixed64)        ← 隨機 64-bit 假 xuid
18 <tick varint>     外層 field 3 (VARINT)         ← 當前 server tick
```

### 精髓：payload_offsets 的重複條目

`payload_offsets` 是 protobuf repeated field。**N 顆 `0x00` byte 在解析時等於 N 個獨立的 varint 條目（每條值為 0）**。

- 音訊本體（`codec_data`）為空、長度 0
- 但伺服器的 parser 必須逐條掃過這上萬個欄位條目
- 這就是「不對稱成本」的核心：**用最便宜的 bytes 換最貴的解析路徑**

### xuid 與 tick 欄位

- `xuid`：每次啟用隨機生成 64-bit 值（`mt19937_64` + `random_device`），推測用於繞過 per-sender 節流/去重，並使伺服器「誰在講話」查找永遠落空（此為推論，程式碼未直接證實動機）
- `tick`：填入當前 server tick，使訊息看起來新鮮、與伺服器時脈同步

---

## 4. 兩組發送 Profile

```cpp
kModeOneProfile = { 65 msgs/datagram,  14 datagrams/tick max, 1475 offsets };
kModeTwoProfile = {  6 msgs/datagram, 119 datagrams/tick max, 16320 offsets };
// config::misc_server_lagger_mode == 1 → ModeTwo，否則 ModeOne
```

| | 每訊息大小 | 每 tick 訊息數上限 | 每 tick 解析條目 | 64 tick 換算 |
|---|---|---|---|---|
| Mode 1 | ~1.5 KB | 910 | ≈ 134 萬條 | ≈ 8,600 萬條/秒 |
| Mode 2 | ~16.3 KB | 714 | ≈ 1,170 萬條 | ≈ 7.45 億條/秒 |

- **Mode 1**：寬而薄 — 大量中小訊息
- **Mode 2**：窄而厚 — 少量巨型訊息（每則 16 KB 的重複欄位）

兩種 mode 皆在每 tick 打出 MB 級流量，同時灌滿客戶端上鏈與伺服器解析路徑。

`voice_payload_t` 的緩衝大小（`10 + 16320 + 1 + 8 + 1 + 5`）即按最大 profile 預留。

---

## 5. 發送機制：複用遊戲內部網路棧

### 5.1 為什麼必須 internal

CS2 走 **SDR（Steam Datagram Relay）加密認證傳輸**，外部無法偽造 UDP 封包進入。
因此整個機制不組封包、不開 socket，而是**在遊戲 process 內借用遊戲自己的傳輸管線**：

```
g_pNetworkMessages（遊戲全域訊息註冊表）
    ↓ vcall(type 22)        查語音訊息的 binding/factory
INetworkMessage 原型
    ↓ 遊戲自己的 CBitRead    把 raw bytes 反序列化成正牌訊息物件
INetChannel（遊戲內部通道物件）
    ↓ vcall(message, -1)    queue 訊息
    ↓ vcall("Server Lagger") SendDatagram 刷成真正的 SDR 加密封包
```

這使攻擊流量與「正常玩家按麥克風說話」在伺服器看來完全同源。

### 5.2 `bit_read_t` — 引擎 `CBitRead` 的鏡像

```cpp
static_assert( sizeof( bit_read_t ) == 0x28 );
static_assert( offsetof( bit_read_t, overflow ) == 0x20 );
```

- 手工重建引擎 bit reader 的記憶體布局（`static_assert` 鎖死尺寸與欄位偏移，保證版本對齊）
- bytes 組幀方式：`varint(payload.size)` 長度前綴 + payload + 4 byte padding（配合 dword-safe 讀取）
- 餵進**遊戲自己的反序列化函式**，確保位元組級相容並觸發與真實語音完全相同的解析路徑
- 解析後檢查 `reader.overflow`，失敗即銷毀訊息返回

### 5.3 發送迴圈（`send_voice_payload`）

- 原型訊息只建一次，之後每份用 clone（vcall）複製 → queue → 銷毀
- 每湊滿 `messages_per_datagram` 個訊息，`SendDatagram` 刷一輪（reason 字串 `"Server Lagger"`）
- **`transport_available` 檢查**：channel 一拒收就停 → 每輪都精準推滿到 net channel 傳送緩衝上限
- 生命週期管理嚴謹：clone 用完即 `destroy_message`（vcall 虛解構），原型最後統一銷毀

---

## 6. 週期控制與主入口（`misc::server_lagger`）

```
config 開關 → NetworkGameClient → 取當前 tick（vcall）
    ↓ runtime.tick == current_tick ?  → 同 tick 不重複觸發
channel = network_client(vcall, 0) → 就緒檢查（vcall 47）
    ↓ amount clamp 到 [1, profile.max]
make_voice_payload(profile, 隨機 xuid, current_tick)
    ↓ send_voice_payload(channel, payload, profile, amount)
```

- **Tick 同步**：每個新 server tick 只爆一輪，攻擊節奏鎖定伺服器處理迴圈，持續性施壓
- 連線中斷/換服時 `runtime` 自動重置（`network_client` 指標變化即重置狀態）
- `amount` 由設定值 clamp 至 profile 上限，防止超量

---

## 7. 防偵測設計

| 手法 | 實現 | 目的 |
|---|---|---|
| vtable 索引混淆 | `xorn(N)` 編譯期 XOR | 躲靜態特徵掃描（VAC） |
| 字串混淆 | `xors("Server Lagger")` | 避免明文字串被 pattern match |
| 無外部網路行為 | 全走遊戲 net stack | 無可疑 socket / import |
| 假 xuid | 每輪隨機 | 繞 per-sender 節流/去重（推論） |

整份程式碼不含任何明文 vtable 呼叫或可搜尋字串。

---

## 8. 為什麼有效：伺服器端成本拆解

以 64 tick 伺服器、Mode 2 滿載為例：

1. **Protobuf 解析**：每 tick 約 1,170 萬個 repeated 欄位條目（≈ 7.45 億條/秒），全在伺服器網路處理路徑上
2. **語音路由/轉發**：CS2 語音為伺服器中繼，解析後仍有廣播成本
3. **上鏈飽和**：每 tick MB 級流量同時打滿客戶端上鏈
4. **tick 預算耗盡** → tick 延遲 → 全服卡頓

客戶端成本僅為：記憶體 copy + queue 呼叫，趨近於零。

---

## 9. 防禦側視角（研究價值所在）

此類濫用的伺服器端緩解思路：

- **結構驗證**：合法短語音的 `payload_offsets` 條目數極少；1,475 / 16,320 條零值條目屬結構異常，可在 schema 驗證層直接拒收
- **一致性檢查**：`codec_data` 為空卻宣告大量 offsets → 邏輯矛盾，高置信度特徵
- **xuid 驗證**：訊息宣稱的 xuid 未對應任何已連線玩家 → 先驗證再進入昂貴的解析/路由路徑
- **Per-tick 速率限制**：對單一 client 的每 tick 語音訊息數與位元組數設上限
- **監控指標**：每 tick voice 訊息量、offsets 條目總數、未知 xuid 比例 — 皆為可直接建置的偵測指標

---

## 10. 術語速查

| 術語 | 意義 |
|---|---|
| SDR | Steam Datagram Relay，Valve 的加密中繼傳輸 |
| `payload_offsets` | 語音 protobuf 的 repeated 欄位，宣告音訊分片邊界 |
| `CBitRead` | Source 引擎的位元流讀取器 |
| `INetChannel` | 遊戲內部網路通道物件，負責可靠/不可靠傳輸 |
| `INVOKE_VCALL` | 對遊戲物件做混淆索引的虛表呼叫 |
| `xorn` / `xors` | 編譯期 XOR 混淆的數值/字串 |
