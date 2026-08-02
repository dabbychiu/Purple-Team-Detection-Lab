# Chain 2 – IR Playbook: ClickFix 釣魚 → Ransomware via ADCS ESC1
完整攻擊鏈的因應指南，從初始釣魚到勒索破壞。

---

## 適用範圍

本 Playbook 涵蓋 Chain 2 全部 13 條已驗證規則，依攻擊階段順序排列，從初始釣魚到勒索破壞。

| 規則 | Stage | 意義 |
|---|---|---|
| Endpoint - Defender - Malicious File Download Detected | 1 | ClickFix 誘導使用者下載惡意 payload |
| Endpoint - Defender - AMSI Malicious Script Blocked | 1 | AMSI 阻擋惡意 PowerShell 內容 |
| Endpoint - Network - C2 Beacon from User Directory | 2 | Sliver C2 已上線，攻擊者建立持久控制通道 |
| Endpoint - Registry - Run Key Persistence | 3 | 攻擊者植入 Run Key 實現持久化 |
| Endpoint - mshta - Remote HTA Network Connection | 3 | LOLBin 執行遠端 HTA，規避偵測 |
| Endpoint - LOLBin - Suspicious Process with Network Parameters | 3 | 系統內建工具帶網路參數執行 |
| AD - SharpHound - Enumeration Tool Execution | 4 | 攻擊者正在列舉 AD 環境，準備提權路徑 |
| AD - ADCS - ESC1 Certificate Request with Enrollee Supplied Subject | 5 | 低權限帳號冒充高權限帳號申請憑證 |
| AD - DomainObject - Directory Replication by Non-DC Account | 6 | 攻擊者執行 DCSync，竊取網域雜湊 |
| AD - SMB - Lateral Movement to File Server via Admin Share | 7 | 攻擊者使用 DA 憑證橫向移動至檔案伺服器 |
| Endpoint - Network - Large Outbound Transfer to Non-Corporate Endpoint | 8 | 機密資料外洩至攻擊者控制的雲端端點 |
| Endpoint - VSS - Shadow Copy Deletion | 9 | 刪除備份還原點，準備勒索加密 |
| Endpoint - Service - Backup and Database Service Stopped | 9 | 停用備份服務，確保加密過程不被干擾 |

**核心判斷原則**：
- **Stage 1-4**：單一規則命中不必然是攻擊，但同一主機/帳號短時間內依序命中兩條以上，就該直接視為進行中的攻擊鏈，不用等到 Stage 5-6 才升級
- **Stage 5（ESC1）**：命中即優先處理，低權限帳號申請非本人憑證是明確攻擊行為，沒有灰色地帶
- **Stage 6（DCSync）**：沒有模糊空間，命中等同整個網域已入侵
- **Stage 9（勒索破壞）**：命中代表破壞已開始，需立即進入緊急模式

---

## 關聯判斷（Stage 1-8）

**命中兩個以上不同階段的行為 → 直接視為進行中攻擊鏈，跳過逐條檢查，進入「加速處理」流程。**

---

## 依 Stage 分流處理

### **Stage 1（ClickFix Initial Access）**

**告警含義**：使用者被誘導執行惡意 PowerShell，或 Defender/AMSI 阻擋了惡意內容下載或執行。需區分三種子規則：AMSI 阻擋代表 MDE 成功防禦但攻擊者可能改換方式；Defender 偵測惡意下載代表 payload 嘗試落地；兩者都命中後若再出現 C2 Beacon，代表攻擊者已繞過防禦。

**初步分類**：
1. 確認觸發來源是否為已知滲透測試主機
2. 確認命中時間是否與合法維運工作重疊
3. 確認 Defender Exclusion Path 是否有異常設定（攻擊者可能先設排除再下載）

**處理流程**：
1. 立即確認目標主機的 `C:\Users\Public\` 或使用者暫存目錄是否有不明可執行檔
2. 若命中主機非白名單 → 隔離該主機的對外連線能力，但**不要立即刪除惡意檔案**——先保留供鑑識，除非有立即擴散風險
3. 確認 Defender Exclusion Path 是否有異常設定，有 → 立即移除排除清單並重新掃描

**升級判斷**：
- AMSI 阻擋後 30 分鐘內同主機命中 C2 Beacon → 確認繞過成功，直接升級

---

### **Stage 2（Sliver C2 上線）**

**告警含義**：`C:\Users\` 路徑下的可執行檔對外建立 HTTPS 連線，Sliver C2 已上線，攻擊者取得對端點的持久控制。

**初步分類**：
1. 確認 `InitiatingProcessFolderPath` 是否為可疑路徑（`C:\Users\Public\`、`%TEMP%` 等）
2. 確認目的 IP 是否為已知雲端服務或企業合法端點
3. 確認連線頻率是否有規律性（C2 beacon 通常有固定間隔）

**處理流程**：
1. **高優先**：立即隔離該端點，防止攻擊者透過 C2 繼續操作
2. 識別 C2 連線目的 IP，加入防火牆封鎖清單
3. 確認該使用者帳號是否已有橫向移動跡象
4. 保留 C2 process 的記憶體 dump 供鑑識分析

**升級判斷**：
- C2 上線後 1 小時內命中 SharpHound 或 ESC1 規則 → 直接升級，攻擊者已進入提權階段

---

### **Stage 3（Persistence + Defense Evasion）**

**告警含義**：攻擊者透過 Registry Run Key 植入持久化後門，並使用 LOLBin（mshta 等）規避偵測。

**初步分類**：
1. 確認 Run Key 值指向的路徑是否為合法程式
2. 確認 mshta/LOLBin 的連線目的地是否為企業內部端點

**處理流程**：
1. **Run Key 命中**：立即移除異常 Run Key 值；確認同一路徑是否有其他惡意 payload；確認該 HKCU Run Key 是在哪個使用者 context 下新增的
2. **LOLBin 命中**：確認執行來源程序（父程序）是否異常；確認目的地 URL/IP 是否已在 C2 封鎖清單內

**升級判斷**：
- Run Key + C2 Beacon 同時命中 → 攻擊者已完成初始立足和持久化，直接升級

---

### **Stage 4（SharpHound AD 枚舉）**

**告警含義**：SharpHound 或等效工具執行了全域 AD 枚舉，攻擊者在收集提權路徑資訊，包含 ADCS 範本、ACL 關係、Session 等。

**處理流程**：
1. 確認執行帳號是否為低權限使用者（若是，代表攻擊者已在規劃提權路徑）
2. 主動審查 AD CS 設定：
   - 確認是否有 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 的憑證範本
   - 確認低權限帳號是否有 Enroll 權限
3. 若發現 ESC1 漏洞範本 → 先撤銷低權限帳號的 Enroll 權限，不用等 Stage 5 才處理

**升級判斷**：
- SharpHound 後 1 小時內命中 ESC1 規則 → 直接升級，攻擊者已找到提權路徑並開始利用

---

### **Stage 5（ADCS ESC1 憑證申請）**

**告警含義**：4887 事件顯示憑證申請者（Requester）與憑證 SAN 的 Principal Name 不符，代表低權限帳號冒充高權限帳號申請憑證，可用於 PKINIT 認證取得 DA TGT。此規則設計已篩除 FP，命中即視為攻擊。

**初步分類**：
1. 確認 `Template` 欄位是哪個憑證範本，確認 ESC1 漏洞範本
2. 確認 `Requester` 與 `PrincipalName` 不符的內容（攻擊者冒充的目標帳號）

**處理流程**：
1. **立即**：
   - 吊銷該序號的憑證（從 CA 管理介面執行）
   - 停用 ESC1 漏洞範本的 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 標誌
   - 撤銷所有低權限帳號對該範本的 Enroll 權限
2. 確認是否已取得 TGT（查詢近期 4768 事件，確認 PKINIT 認證是否成功）
3. 若 4768 已命中（PKINIT 成功）→ 立即假設 DA 級憑證已取得，進入 DCSync 因應模式

**升級判斷**：
- ESC1 規則命中 → 無條件升級至最高優先，預期即將或已發生 DCSync

---

### **Stage 6（DCSync）**

**告警含義**：非 DC 帳號對網域執行了複寫請求（AccessMask 0x40000，含 Replicating Directory Changes GUID）。這一步沒有模糊空間：命中等同整個網域雜湊（含 krbtgt）已被讀取，視為已入侵。

**處理流程（緊急模式）**：
1. **立即停用觸發帳號**，並撤銷所有現有 session/票證
2. **krbtgt 密碼輪替兩次**（間隔至少數小時，因 krbtgt 保留前一版雜湊，只轉一次不足以讓已竊取的雜湊失效）
3. 吊銷 ESC1 所申請的憑證，並確認 CA 稽核紀錄中是否有其他異常申請
4. **強制輪替所有高權限帳號密碼**，不限於單一帳號——雜湊外洩的影響範圍是整個目錄，需要系統性清消
5. 確認 DCSync 複寫的範圍（是否針對單一帳號或整個目錄），決定後續輪替範圍

**升級判斷**：
- DCSync 規則命中 → 無條件升級至最高優先級

---

### **Stage 7（橫向移動 SRV-FILE）**

**告警含義**：DA 帳號（或使用 DA hash 的帳號）透過 SMB Type 3 登入至檔案伺服器，攻擊者正在存取共享資料。

**初步分類**：
1. 確認登入來源 IP 是否為已知企業端點
2. 確認登入帳號是否為已知合法管理員帳號（此規則 FP 率偏高，需搭配白名單 Tuning）

**處理流程**：
1. 確認 SRV-FILE 上的共享資料是否有異常存取（大量讀取、異常時段）
2. 若已確認 DCSync（Stage 6 命中），此時登入帳號等同 DA 級，立即隔離 SRV-FILE
3. 確認共享資料是否有被下載或修改的跡象，評估資料外洩風險

**升級判斷**：
- 橫向移動 + DCSync 相繼命中 → 直接視為全網域失陷，進入全面圍堵

---

### **Stage 8（資料外洩）**

**告警含義**：rclone 或等效工具從端點對外傳輸資料至非企業端點（攻擊者控制的 S3/MinIO）。一旦命中，假設資料已外洩，不論傳輸是否成功（ConnectionFailed 也算）。

**處理流程**：
1. 立即封鎖目的地 IP/Port（9000、443 等外洩目標）
2. 確認外洩範圍：查詢 rclone 的 CommandLine 確認外洩的來源路徑和目的 bucket
3. **資料外洩即視為 Double Extortion 的前置動作**，準備進入勒索應變模式
4. 通知法務/DPO，啟動資料外洩事件通報流程（依 GDPR/個資法規定）

**升級判斷**：
- 資料外洩命中 → 直接升級，啟動資料外洩通報流程

---

### **Stage 9（勒索破壞）**

**告警含義**：VSS Shadow Copy 被刪除、備份服務被停止。命中代表破壞已開始，且攻擊者可能正在進行資料加密。

**處理流程（緊急模式）**：
1. **立即隔離受影響主機**，防止勒索軟體持續橫向加密其他主機
2. 確認 offsite/cloud 備份的完整性（是否在攻擊發生前的備份點）
3. 不要支付贖金前，先確認備份還原可行性
4. 回頭確認資料外洩範圍（Stage 8），評估 Double Extortion 風險
5. 保留受影響主機的完整狀態供鑑識比對

**升級判斷**：
- 勒索破壞規則任一命中 → 無條件升級至最高優先，同步通知管理層

---

## 加速處理流程（關聯命中 ≥2 階段時）

當同一主機/帳號在 30 分鐘內觸發兩條以上不同階段的規則時，**不用逐條 triage**，直接：
1. 假設攻擊已進入橫向移動前期，通知高價值資產 owner 提高戒備
2. 主動查詢該來源近 2 小時內的 C2 beacon、ESC1 申請、DCSync 事件（提前檢查，不等規則自己觸發）
3. 立即確認 AD CS 的憑證申請日誌，查詢是否有 Requester ≠ Principal Name 的異常申請
4. 銜接 Stage 6-9 的圍堵流程，視為同一起事件的延伸

---

## 升級標準（Escalation）

以下任一情況，立即升級，不等待調查完成：

- **Stage 5（ESC1）或 Stage 6（DCSync）規則命中**（無論範圍大小）
- **Stage 9（勒索破壞）任一規則命中**
- **Stage 1-4 任兩條規則於 30 分鐘內同一主機/帳號命中**
- C2 Beacon 目的地 IP 確認為攻擊者基礎設施
- 觸發帳號為既有特權帳號（非一般使用者）

---

## 需保存的證據

- **ESC1 命中當下的完整 4886/4887 事件**（`Requester`、`PrincipalName`、`CertificateTemplate` 原始值）
- **DCSync 命中當下的完整 4662 事件**（`Properties` GUID 值，供確認複寫權限範圍）
- **C2 beacon 的 DeviceNetworkEvents 完整記錄**（RemoteIP、Port、ProcessCommandLine）
- **觸發帳號前後 24 小時的完整 4624/4688 活動**
- **rclone 執行的完整 CommandLine**（確認外洩目的地和來源路徑）
- **SRV-FILE 的完整 SecurityEvent**（確認橫向移動時間軸）

---

## 已知誤判（Known False Positives）

| 誤判來源 | 涉及 Stage | 處置 |
|---|---|---|
| OneDrive 或合法應用程式從 Users 路徑對外連線 | Stage 2 | 建立已知合法程式白名單（OneDrive.exe 等） |
| IT 人員手動執行 PowerShell 維運腳本 | Stage 1 | 建立已授權測試主機/帳號清單 |
| 授權滲透測試主機執行 SharpHound | Stage 4 | 建立已授權測試主機清單 |
| IT 管理員合法代發憑證（Requester ≠ Principal Name 的合法情境） | Stage 5 | 建立已授權代發流程白名單，確認申請流程是否合規 |
| 合法 IT 管理員遠端管理 SRV-FILE | Stage 7 | 建立已知合法來源 IP 白名單；單獨命中不建議直接告警，需關聯 DCSync 事件 |
| rclone 合法用於備份至雲端 | Stage 8 | 確認目的地是否為企業授權的雲端端點 |
| 合法備份軟體的 VSS 管理操作 | Stage 9 | 建立已知合法備份工具白名單 |


**建議**：白名單外的任何命中直接視為高優先事件，不需額外人工判斷是否誤判。

---

## 快速參考

| 階段 | 優先級 | 第一動作 | 關鍵證據 |
|---|---|---|---|
| 1（ClickFix） | 高 | 確認 payload 是否已落地執行，移除 Exclusion Path | Defender 告警內容、AMSI 偵測欄位 |
| 2（C2） | **最高** | 隔離端點，封鎖 C2 IP | RemoteIP、InitiatingProcessFolderPath |
| 3（持久化/LOLBin） | 高 | 移除 Run Key、封鎖 LOLBin 目的地 | RegistryValueData、mshta CommandLine |
| 4（SharpHound） | 高 | 主動審查 ADCS 範本設定 | FileName、ProcessCommandLine |
| 5（ESC1） | **最高** | 吊銷憑證、關閉漏洞範本 Enroll 權限 | Requester vs PrincipalName（4887） |
| 6（DCSync） | **最高** | 停用帳號 + krbtgt 輪替兩次 | 複寫範圍 + Properties GUID |
| 7（橫向移動） | **最高** | 隔離 SRV-FILE，確認存取範圍 | IpAddress、TargetUserName（4624） |
| 8（外洩） | **最高** | 封鎖目的地 IP、啟動通報流程 | rclone CommandLine、RemoteIP |
| 9（勒索破壞） | **最高** | 隔離受影響主機、確認備份可用性 | vssadmin CommandLine、服務停用記錄 |
