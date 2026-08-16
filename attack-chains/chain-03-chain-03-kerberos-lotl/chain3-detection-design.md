# detection-design.md
## Chain 3 偵測工程設計紀錄

> 這份文件記錄的不是「規則怎麼寫」，而是「為什麼這樣設計、每個假設怎麼被真實遙測推翻、以及推翻之後學到什麼」。它是 flow.md 的設計層補充，也是三層方法論在實際執行中的校準日誌。

---

## 一、三層偵測方法論

Chain 3 的核心主張是：同一個攻擊技術可以有三種不同深度的偵測，攻擊者繞過第一層時第二層接住，繞過第二層時第三層接住。

| 層級 | 偵測依據 | 韌性 | 被繞過條件 | 誤報率 |
|---|---|---|---|---|
| 工具簽章層 | 已知攻擊工具的命令列特徵（如 SharpHound.exe） | 最低 | 換工具、改名、LOTL | 最低 |
| 原語層 | 協定/API 的本質行為（4662/4768/4769，工具無關） | 中 | 低速稀釋門檻、AES 降級規避 | 中 |
| 行為層 | 跨事件的因果落差（索票無登入、DCSync 後接票證） | 最高 | 極難規避（需消除因果痕跡） | 中偏高（未調校時）→ 低（白名單後） |

### 三層的正確用法：不是每個技術都硬湊三層

判斷一層該不該做，只有一個問題：**這層能不能提供其他層給不了的資訊？**

- **AS-REP Roasting**：`PreAuthType==0` 近乎確定異常，原語層一層就夠。行為層（批次收割）的價值不是補漏，而是把「設定疏失」升級成「確認系統性攻擊」。這是 Chain 3 裡「原語層即足夠」的範例。
- **低速 LDAP 偵察**：4662 噪音大、單事件不可疑，**必須**靠行為層才能偵測。這是「原語層不夠、行為層非做不可」的範例。
- **Golden Ticket**：攻擊在記憶體完成，無工具簽章，無乾淨原語事件（成功時不留 4768），**只能**靠行為層（TGS 無 AS-REQ 因果落差）或環境限制層（失敗的 KDC_ERR_TGT_REVOKED）。這是「為什麼必須有行為層」的最強論證。

這種「層數應由偵測難度決定，不是機械地套三層」的判斷，是 detection engineering 和「貼規則範本」最大的差距。

---

## 二、校準案例集

以下三個案例是 Chain 3 執行過程中，規則假設被真實遙測推翻、並完成校準的完整記錄。它們共同說明一件事：**規則寫出來不等於規則有效，每個假設都需要用真實流量驗證。**

---

### 案例一：ObjectType 門檻校準（Stage 1 低速 LDAP 偵察）

**初始假設**
系統性 AD 偵察會枚舉大量物件類別，門檻設 `DistinctObjectTypes >= 5`，憑直覺認為攻擊者至少會查到 5 種不同的物件類型。

**執行攻擊後發現**
Alice 用 DirectorySearcher 對 user/group/computer 做完整枚舉，DC01 本機 4662 事件分析顯示：實際只產生 **3 種 ObjectType GUID**（bf967aba=user、bf967a9c=group、bf967a86=computer）。

**結論**
3 < 5，門檻設 >=5 的規則永遠不會觸發——一條看似合理的規則，在真實環境是死的。

**校準**
門檻改為 `>= 3`，對應「完整枚舉三大類物件」的真實上限。正常單一查詢產生 1 種 ObjectType，系統性全枚舉產生 3 種，`>= 3` 精準區分兩者。

**同時發現**
AccessMask 初版寫 `has_any("0x10","0x100")`（照通用文件），環境實測：機器帳號背景活動為 `0x1`、使用者 LDAP 屬性讀取為 `0x10`。收斂為 `== "0x10"`，同時加入 `SubjectAccount startswith "CORP\\"` 排除本機帳號 labadmin 的 FP（labadmin 也觸發了行為層規則，因為它的管理操作跨 40 分鐘，踩過 SpanMin 門檻）。

**學到的**
門檻必須用真實遙測校準，不能沿用通用文件的假設值。任何寫死的數字都是一個「等待被推翻的假設」。

---

### 案例二：加密類型假設失效（Stage 2/3 AS-REP Roasting / Kerberoasting）

**初始假設**
Kerberoasting 攻擊者偏好 RC4（`TicketEncryptionType == "0x17"`），因為 RC4 hash 比 AES hash 更容易離線破解。這是業界通用文件和多數規則範本的預設假設。

**執行攻擊後發現（Stage 2 AS-REP）**
DC01 的 4768 事件顯示 `TicketEncryptionType = 0x12`（AES256-CTS-HMAC-SHA1-96），不是 0x17。

**執行攻擊後發現（Stage 3 Kerberoasting）**
impacket 預設嘗試 RC4 請求，DC 直接回應 `KDC_ERR_ETYPE_NOSUPP`——DC 根本拒絕 RC4 請求。改用 `-k -no-pass`（先取 AES TGT 再索票）才成功，取得的 hash 格式是 `$krb5tgs$18$`（AES256），不是 `$krb5tgs$23$`（RC4）。

**結論**
你的 Chain 1 RC4 規則（`TicketEncryptionType == "0x17"`）在這個環境**永遠不會觸發**——不是規則寫錯，是環境的 Server 2025 AES 強制政策讓 RC4 根本不存在。這個規則在這個環境是一條空規則。

**校準**
- Stage 2 AS-REP 規則：移除 `TicketEncryptionType` 限定，只靠 `PreAuthType == "0"` 作為核心指紋（因為 AS-REP Roasting 的本質是無預先驗證，加密類型是次要的）
- Stage 3 Kerberoasting 規則：移除 enctype 限定，改看「索票量」（Multi-SPN 聚合）和「索票無登入」的行為指紋

**延伸洞察**
這帶出一個更深的偵測工程判斷：**不要以加密類型為偵測依據，要以攻擊行為為偵測依據。** 加密類型是環境設定，可能隨政策改變；「批次對多個 SPN 索票」是攻擊意圖，換了加密類型也一樣存在。

---

### 案例三：EventData XML 欄位未被 DCR 原生解析（Stage 2/3 欄位校準）

**初始假設**
Sentinel 的 `SecurityEvent` 表中，4768/4769 事件的 `PreAuthType`、`TicketEncryptionType`、`TargetUserName` 等欄位可以直接用欄位名查詢（如 `| where PreAuthType == "0"`）。

**執行後發現**
Sentinel 直接查詢 `PreAuthType` 報錯：
```
The name 'PreAuthType' does not refer to any known column, table, variable or function.
```

查詢原始 `EventData` 欄位，確認這些欄位全部藏在 EventData XML 字串裡：
```xml
<Data Name="PreAuthType">0</Data>
<Data Name="TicketEncryptionType">0x12</Data>
```

DCR 只解析了常用欄位（TargetUserName、IpAddress、Computer 這類），冷門的 Kerberos 認證欄位沒有被原生解析成獨立 column。

**校準**
全面改用 `extract()` 從 EventData XML 取值：
```kql
| extend PreAuthType = extract(@'Name="PreAuthType">([^<]+)<', 1, EventData)
| extend EncType = extract(@'Name="TicketEncryptionType">([^<]+)<', 1, EventData)
```

**學到的**
**DC 本機有的欄位，Sentinel 不一定原生解析。** 這是 detection engineer 在 Sentinel 上寫規則時最常撞牆的問題之一——`Get-WinEvent` 能看到的欄位，KQL 裡不一定能直接查。遇到「no such column」報錯，第一個反應是去看 EventData 的原始 XML，找欄位的真實名稱，再用 `extract()` 取值。

這個坑踩過一次就不會忘：`Get-WinEvent` 解 XML ≠ Sentinel KQL 能直接用。

---

## 三、行為層的誤判取捨

行為層是三層中韌性最高的，但也是**最容易誤判的**。這個反直覺的現象值得記錄清楚。

### 為什麼行為層誤判率偏高

行為層抓的是「持續、規律、跨長時間」的模式。問題是這個模式和正常的機器式活動**在資料上幾乎同型**：

- 監控代理程式（每 5 分鐘查一次 AD 健康狀態）
- 資產盤點工具（定時全網域掃描）
- Azure AD Connect 同步（規律地讀取物件）

低速攻擊的「潛伏」和正常服務的「規律」難以區分——這是行為層誤判的核心難點。

### 三層誤判率的真實排序

| 層級 | 誤判率 | 為什麼 |
|---|---|---|
| 工具簽章層 | 最低 | 工具名幾乎不可能是正常活動 |
| 原語層 | 中（未調校）→ 低（調校後） | 4662 量大，但聚合 + 濾機器帳號後可壓到零 |
| 行為層 | 中偏高（未調校）→ 低（白名單後） | 天生跟機器式規律活動撞型，但白名單後可管理 |

**實際驗證**：Stage 1 的行為層規則命中了 labadmin（本機管理員帳號），因為它的管理操作跨了 40 分鐘、有 4 個活躍 bin，踩過 `SpanMin >= 25 and ActiveBins >= 4` 門檻。這是行為層「機器式規律活動」FP 的活生生範例。

**修正**：加入 `SubjectAccount startswith "CORP\\"` 排除本機帳號，本機帳號的 AD 查詢不走網域 Kerberos，不是典型的攻擊路徑。

### 壓誤判的三個方法

1. **白名單服務帳號**：誤判源幾乎都是可列舉、固定的服務帳號，一次列好長期有效
2. **只看人類帳號**：正常人類使用者不會持續 2 小時規律查 AD，普通使用者帳號觸發即高可信（指向被植入自動化偵察的淪陷帳號）
3. **看間隔規律性**：機器間隔有特徵（固定或偽隨機），人類查詢零星不規律

---

## 四、環境限制作為偵測設計的輸入

Chain 3 遇到了四個「攻擊被環境擋住」的斷點，但這些斷點本身都有偵測工程的含義：

### Windows Server 2025 PAC 驗證——Golden/Diamond/Sapphire Ticket

**現象**：六種 Golden Ticket 方式（NTLM hash、AES256、Diamond、extra-pac、RID 500、KdcPacRequestorEnforcement=0）均被 `KDC_ERR_TGT_REVOKED` 拒絕。Silver Ticket 仍有效（SRV-FILE 服務主機保護弱於 DC）。

**偵測含義**：在開啟 PAC 驗證的現代環境，Golden Ticket 嘗試本身就是偵測機會——雖然 Server 2025 不在 Security Log 留下失敗 4768，但 Silver Ticket 的「SRV-FILE 有 4624 但 DC 無 4769」這個因果落差反而是更乾淨的偵測訊號。

**核心洞察**：**防禦加固改變了偵測策略。** 未加固環境靠「因果落差」偵測成功的 Golden Ticket；Server 2025 環境攻擊被擋，偵測焦點轉向 Silver Ticket 的盲區矛盾。

### MDE 攔截 LSASS——comsvcs MiniDump

**現象**：comsvcs MiniDump 在 EMPLOYEE01 和 DC01 均被 MDE（HackTool:Win32/DumpLsass.H）在 rundll32 執行層級攔截。

**偵測含義**：MDE 的工具簽章層在這裡有效——與 Stage 1 LOTL 讓工具簽章層失效形成對比。這說明三層方法論的另一面：**特徵明顯的攻擊，工具簽章層就夠了**；特徵不明顯的攻擊（LOTL），才需要往原語層和行為層走。Stage 4b gMSA 是 LSASS 被擋後的替代路徑，走 4662 SACL 偵測。

### Server 2025 Protocol Transition 限制——RBCD S4U2Self

**現象**：RBCD 屬性寫入成功，但 S4U2Self 被 Server 2025 的 Protocol Transition 限制擋住（KDC_ERR_C_PRINCIPAL_UNKNOWN）。六種帳號/格式組合均失敗，impacket v0.14.0 對此不相容。

**偵測含義**：RBCD 的偵測重點在「寫入端」（5136 屬性變更），而非「使用端」（S4U 取票）。寫入端是攻擊者鞏固路徑的時機，比等到 S4U 取票時才偵測更早。問題是 impacket LDAP channel 在此環境不觸發 5136，即使設了 SACL。這個根本原因未確認。

### Windows 11 GPO CSE——Immediate Task / Startup Script

**現象**：ScheduledTasks.xml、scripts.ini/test.bat 均成功寫入 SYSVOL，GPT.INI 也更新了 CSE GUID，但 EMPLOYEE01 重開機後下游執行未觸發。GPO Operational Log 無 Scheduled Tasks CSE 處理記錄。

**偵測含義**：GPO 的偵測重點在「寫入端」（5136 GPO 物件變更 + SYSVOL 異常檔案）而非「下游執行端」（端點程序啟動），因為下游執行在現代 Windows 11 上受到更嚴格的 CSE 觸發限制。5136 的 impacket LDAP channel 問題同樣出現，根本原因與 RBCD 相同。

---

## 五、票證鍛造的偵測難度光譜

| 票種 | 偵測邏輯 | 難度 | 此環境可驗證 |
|---|---|---|---|
| Golden Ticket | TGS 無 AS-REQ 因果缺失 | 中 | 🔵 攻擊被擋，無成功遙測 |
| Silver Ticket | 服務有 4624 但 DC 無 4769 | 低（一旦找到盲區） | ✅ 驗證通過 |
| Diamond Ticket | AS-REQ 帳號 ≠ TGS 帳號（同來源 IP） | 高 | 🔵 同 Golden，被擋 |
| Sapphire Ticket | S4U Transited Services 非空 + 高權帳號 | 最高 | 🔵 同上 |

**核心洞察**：票證「真實性」越高，偵測越難。Golden Ticket 完全偽造，因果落差最明顯；Sapphire Ticket 連 PAC 都是真實的，標準日誌幾乎看不到指紋。在你的 Server 2025 環境，這四種票都被擋——防禦做到了「攻擊無法成功」，但同時也讓「攻擊嘗試本身」的訊號消失（不留 Security Event）。這個「防禦有效但偵測訊號也消失」的矛盾，是現代 AD 加固的真實困境。

---

## 六、偵測規則腐化的時間維度

Chain 3 執行過程中，有一個隱性的發現值得記錄：**規則會隨環境和時間腐化。**

- Chain 1 的 RC4 Kerberoasting 規則在當時驗證過，但 Chain 3 的環境（同一個 DC01）已經是 Server 2025 AES 強制，那條規則在現在的環境是死的。
- 規則設計時的假設（RC4 普遍、門檻 >=5、欄位可直接查）在環境升級或政策變更後可能全部失效。

這是 detection engineering 和「一次性部署」最大的差距：**偵測規則需要持續驗證，不是部署一次就永久有效。** 這也是為什麼 purple team lab 的「攻擊驅動偵測」比靜態的規則清單有更長的生命週期——每次攻擊都是對現有規則的壓力測試。

---

## 附錄：校準前後對照

| Stage | 校準項目 | 校準前 | 校準後 |
|---|---|---|---|
| 1 | ObjectType 門檻 | `>= 5` | `>= 3` |
| 1 | AccessMask 值 | `has_any("0x10","0x100")` | `== "0x10"` |
| 1 | 帳號 filter | `!endswith "$"` | `!endswith "$" + startswith "CORP\\"` |
| 2/3 | 加密類型假設 | `TicketEncryptionType == "0x17"` | 移除限定，靠 PreAuthType/行為 |
| 2/3 | 欄位解析方式 | 直接用欄位名 | `extract()` 從 EventData XML |
| 5 | DCSync AccessMask | `0x40000`（通用文件） | `0x100`（環境實測） |
| 7b | 強制驗證偵測資料源 | SecurityEvent 4769 | MDE DeviceNetworkEvents（DC 對外 SMB） |
