# chain-03-kerberos-lotl
## IR Playbook: Kerberos 票證濫用 → 委派濫用 → 持久化

完整攻擊鏈的因應指南，覆蓋低速 LDAP 偵察到 ACL/GPO 持久化。

---

## 適用範圍

本 Playbook 涵蓋 Chain 3 全部已驗證規則，依攻擊階段順序排列。

| 規則 | Stage | 意義 |
|---|---|---|
| AD - Recon - Anomalous LDAP Object Enumeration | 1 | 非工具 LDAP 枚舉，攻擊者正在收集 AD 拓撲 |
| AD - Recon - Low-and-Slow LDAP Enumeration | 1 | 低速持續枚舉，攻擊者刻意規避門檻型偵測 |
| AD - KDC - AS-REP Roasting Pre-Auth Disabled | 2 | 無預先驗證帳號被索取 TGT，可離線破解 |
| AD - KDC - AS-REP Roasting Bulk Harvesting | 2 | 同源批次對多帳號 AS-REP 收割，確認系統性攻擊 |
| AD - KDC - Kerberoasting Multi-SPN Harvesting | 3 | 批次索取多個服務票，正在收割可破解 hash |
| AD - KDC - Kerberoast Ticket Without Logon | 3 | 票索了但不用，確認票被拿去離線破解 |
| AD - gMSA - Unauthorized ManagedPassword Attribute Access | 4b | 非授權帳號嘗試讀取 gMSA 密碼，替代憑證竊取路徑 |
| AD - DomainObject - Directory Replication by Non-DC Account | 5 | DCSync，網域 hash 全數外洩 |
| AD - DCSync Followed by Anomalous KRBTGT Activity | 5 | DCSync 後緊接票證活動，確認攻擊鏈推進 |
| AD - Kerberos - Golden Ticket Attempt Rejected | 6a | 偽造票被 DC PAC 驗證拒絕，攻擊嘗試留下痕跡 |
| AD - Kerberos - Silver Ticket Service Access Without DC Log | 6b | 服務有存取但 DC 無 4769，Silver Ticket 繞過 DC |
| AD - Pass-the-Ticket - Anomalous Kerberos Logon | 6d | Kerberos 登入來自非預期來源 IP |
| AD - Pass-the-Ticket - Forged TGT Lateral Movement Behavioral | 6d | 同帳號同 IP 短時間打多台主機，票證橫向移動 |
| AD - Delegation - RBCD Attribute Modification | 7a | msDS-AllowedToActOnBehalfOfOtherIdentity 被寫入 |
| AD - Coerced Authentication Anomaly | 7b | DC 機器帳號票證來自非 DC 網段，強制驗證指紋 |
| AD - ACL - GenericAll DACL Grant on Container | 8 | OU/GPO 容器安全性描述元被修改，持久化前置 |
| AD - GPO - Unauthorized Group Policy Modification | 8 | 非授權帳號修改 GPO 物件 |
| AD - GPO Abuse to Endpoint Execution | 8 | GPO 變更後端點下游執行，確認 GPO 濫用生效 |

**核心判斷原則**：
- **Stage 1-3**：單條命中為中優先，同主機/帳號依序命中兩條以上直接視為攻擊鏈進行中
- **Stage 4b（gMSA）**：非授權讀取嘗試即中高優先，確認授權清單後決定升級
- **Stage 5（DCSync）**：無模糊空間，命中等同整個網域 hash 已外洩
- **Stage 6（票證鍛造）**：Silver Ticket 在現代環境更易成功，DC 完全無記錄是關鍵
- **Stage 7-8（委派/持久化）**：屬性寫入即為攻擊者鞏固陣地的訊號，需立即溯源

---

## 關聯判斷（Stage 1-5）

**任兩個不同階段的規則在同一帳號/來源 IP 命中 → 直接視為進行中攻擊鏈，進入加速處理流程。**

特別關注以下組合：
- LDAP 枚舉（Stage 1）+ AS-REP/Kerberoasting（Stage 2/3）→ 攻擊者已完成目標枚舉並開始收割
- DCSync（Stage 5）+ 任何票證規則（Stage 6）→ Golden Ticket 場景，全域 hash 已外洩且正在利用
- RBCD 寫入（Stage 7a）+ 強制驗證（Stage 7b）→ 委派濫用攻擊鏈完整串起

---

## 依 Stage 分流處理

### **Stage 1（低速 LDAP 偵察）**

**告警含義**：非工具的 LDAP 枚舉（DirectorySearcher/原生 API）在 DC 上產生 4662 事件。攻擊者用 LOTL 手法枚舉 user/group/computer，或以低速、跨時間窗的方式規避門檻型偵測。

**初步分類**：
1. 確認觸發帳號是否為已知管理員帳號（AD 管理工具日常操作）
2. 確認觸發時間是否與合法維運工作重疊
3. 確認 ObjectType 種類數（>=3 代表系統性枚舉）

**處理流程**：
1. 查詢同帳號近 1 小時內是否有 AS-REP/Kerberoasting 事件（Stage 2/3 先行確認）
2. 確認觸發帳號的正常工作性質——網域一般使用者不應有大量 LDAP 查詢
3. 若行為層規則（低速枚舉）命中，擴大查詢視窗至 6 小時，確認枚舉範圍

**升級判斷**：
- 同帳號 1 小時內命中 AS-REP 或 Kerberoasting 規則 → 直接升級，攻擊者已找到目標開始收割

---

### **Stage 2（AS-REP Roasting）**

**告警含義**：4768 事件顯示 PreAuthType=0，代表無預先驗證的帳號被索取 TGT，攻擊者取得可離線破解的 hash。批次收割規則（同源短時間多帳號）幾乎排除設定疏失的可能。

**初步分類**：
1. 確認被索取的帳號（TargetUser）是否為已知無預先驗證的合法服務帳號
2. 確認來源 IP（SrcIp）是否為授權管理工作站

**處理流程**：
1. **立即**：清點所有 DoesNotRequirePreAuth=True 的帳號，確認哪些帳號確實需要此設定
2. 對不必要的帳號重新啟用預先驗證（`Set-ADAccountControl -DoesNotRequirePreAuth $false`）
3. 對已被索取 TGT 的帳號強制重設密碼
4. 查詢同來源 IP 近期的 LDAP 枚舉事件，確認攻擊者是否已完成偵察

**升級判斷**：
- 批次收割規則（TargetedAccounts >=2）命中 → 升級，確認為系統性攻擊而非偶發設定疏失

---

### **Stage 3（Kerberoasting）**

**告警含義**：攻擊者對設有 SPN 的服務帳號批次索取服務票，票以服務帳號密碼加密，可離線破解。「索票無登入」行為層規則確認票被拿去破解而非實際使用。

**初步分類**：
1. 確認被索取的服務帳號（ServiceName）是否為高權限帳號（Domain Admins 成員）
2. 確認索票來源 IP 是否為已知服務伺服器（合法服務存取 vs. 攻擊者）

**處理流程**：
1. 確認被 Kerberoast 的服務帳號密碼強度，弱密碼帳號立即重設
2. 評估服務帳號是否有不必要的高權限，考慮降權
3. 若 Domain Admin 帳號（如 admin）的 SPN 被 Kerberoast → 立即升級，後果等同 DCSync

**升級判斷**：
- 高權限帳號 SPN 被 Kerberoast + 「索票無登入」同時命中 → 升級，密碼可能已被破解

---

### **Stage 4b（gMSA 非授權讀取）**

**告警含義**：4662 事件顯示非授權帳號嘗試讀取 gMSA 物件的 msDS-ManagedPassword 屬性。被拒絕代表 AD 授權機制有效，但嘗試本身即為攻擊指紋。

**初步分類**：
1. 確認觸發帳號是否在 PrincipalsAllowedToRetrieveManagedPassword 清單中（清單外則確認為非授權）
2. 確認 gMSA 帳號的服務用途和權限範圍

**處理流程**：
1. 確認觸發帳號是否有其他異常活動（已淪陷帳號的橫向嘗試）
2. 審查 gMSA 帳號的授權讀取清單，確認是否需要收緊
3. 若觸發帳號同時有 LDAP 枚舉或 Kerberoasting 記錄 → 確認攻擊者已在系統性嘗試憑證竊取

**升級判斷**：
- 同帳號同時有 Stage 1-3 記錄 → 升級，攻擊者正在嘗試多條憑證竊取路徑

---

### **Stage 5（DCSync）**

**告警含義**：非 DC 帳號對網域執行複寫請求（AccessMask 0x100，含 Replicating Directory Changes GUID）。命中等同整個網域 hash（含 krbtgt）已被讀取。

**處理流程（緊急模式）**：
1. **立即停用觸發帳號**並撤銷所有現有 session
2. **krbtgt 密碼輪替兩次**（間隔至少數小時，確保前一版 hash 失效）
3. 強制重設所有高權限帳號密碼
4. 查詢 DCSync 後 2 小時內的票證活動（行為層規則）確認是否已進入票證鍛造階段
5. 確認 DCSync 觸發帳號的權限來源（WriteDACL/GenericAll 的 ACL 鏈需一並清理）

**升級判斷**：
- DCSync 規則命中 → 無條件升級至最高優先

---

### **Stage 6（票證鍛造與橫向移動）**

**告警含義**：

- **Golden Ticket 嘗試被拒**（6a）：DC PAC 驗證拒絕偽造票，攻擊者曾嘗試但在此環境（Server 2025）失敗
- **Silver Ticket 存取**（6b）：SRV-FILE 有 4624 登入但 DC 無對應 4769，票完全繞過 DC，是唯一的偵測視窗
- **Pass-the-Ticket 橫向**（6d）：Kerberos 登入來自非預期 IP 或同帳號短時間打多台

**初步分類（Silver Ticket 優先）**：
1. 確認 SRV-FILE 的 4624 帳號（TargetUserName）是否與 DC 4769 對應
2. 確認登入來源 IP（IpAddress）是否為已知授權主機

**處理流程**：
1. **Silver Ticket**：立即輪替 SRV-FILE 機器帳號密碼（`Reset-ComputerMachinePassword`），使現有 Silver Ticket 失效
2. **Pass-the-Ticket**：確認哪些主機被存取，評估資料存取範圍
3. 確認攻擊者是否已從 DCSync 取得機器帳號 hash（前置條件），若是則擴大輪替範圍

**升級判斷**：
- Silver Ticket + DCSync 相繼命中 → 確認攻擊鏈完整，立即進入全面圍堵

---

### **Stage 7（委派濫用）**

**告警含義**：

- **RBCD 寫入**（7a）：msDS-AllowedToActOnBehalfOfOtherIdentity 被寫入，攻擊者已獲得代理存取目標服務的能力
- **Unconstrained Delegation + 強制驗證**（7b）：DC 機器帳號票證來自非 DC 網段，PetitPotam/PrinterBug 強制驗證已成功，MDE 顯示 DC 對外 SMB 連線

**處理流程**：
1. **RBCD**：
   - 確認哪個電腦物件的 msDS-AllowedToActOnBehalfOfOtherIdentity 被修改
   - 清除該屬性（`Set-ADComputer -Clear msDS-AllowedToActOnBehalfOfOtherIdentity`）
   - 審查寫入帳號的權限來源
2. **Unconstrained Delegation**：
   - 確認哪台機器設有 TrustedForDelegation，評估是否業務必要
   - 若非必要，移除 TrustedForDelegation 設定
   - 輪替 DC 機器帳號密碼（應對已捕獲的 NTLMv2 hash）

**升級判斷**：
- RBCD 寫入 + DCSync 在同一帳號鏈上 → 升級，攻擊者正在鞏固委派路徑

---

### **Stage 8（ACL/GPO 持久化）**

**告警含義**：

- **ACL 修改**：OU/GPO 容器的 nTSecurityDescriptor 被非授權帳號修改，攻擊者植入 GenericAll 控制權
- **GPO 修改**：groupPolicyContainer 物件被修改，攻擊者正在注入惡意設定
- **GPO 下游執行**：GPO 變更後端點出現 startup/task 執行，GPO 濫用已生效

**處理流程**：
1. **ACL 修改**：
   - 確認哪個 OU/容器的 ACL 被修改，使用 `(Get-Acl).Access` 確認異常 ACE
   - 移除異常 ACE（`Remove-ADPermission` 或 ADSI Edit）
   - 重設 AdminSDHolder，防止 SDProp 定期恢復攻擊者設定
2. **GPO 修改**：
   - 確認哪個 GPO 被修改，使用 `Get-GPOReport` 審查當前設定
   - 若 SYSVOL 有惡意檔案（ScheduledTasks.xml、scripts.ini）立即刪除
   - 強制所有受影響機器重新套用 GPO（`gpupdate /force /sync`）
3. **GPO 下游執行命中**：
   - 隔離受影響端點，確認執行了什麼命令
   - 確認是否為持久化 backdoor（如 Run Key、Scheduled Task）

**升級判斷**：
- GPO 下游執行規則命中 → 無條件升級，攻擊者已在端點取得執行能力

---

## 加速處理流程（關聯命中 >=2 階段時）

當同一帳號/來源 IP 在 30 分鐘內觸發兩條以上不同階段規則時：
1. 跳過逐條 triage，直接假設攻擊鏈正在推進
2. 主動查詢該帳號近 6 小時內的 LDAP 枚舉、AS-REP、Kerberoasting、DCSync 事件（不等規則自動觸發）
3. 確認 SYSVOL 和 AD 委派屬性是否已被修改
4. 通知 AD 管理員暫停高權限帳號的異常活動

---

## 升級標準（Escalation）

以下任一情況，立即升級：

- **Stage 5（DCSync）命中**（任何規模）
- **Stage 6b（Silver Ticket）命中**（DC 無記錄即確認）
- **Stage 8 GPO 下游執行命中**
- **Stage 1-3 任兩條在 30 分鐘內同一帳號命中**
- Unconstrained Delegation 強制驗證確認（DC 對外 SMB 非預期）
- 觸發帳號為既有特權帳號或服務帳號

---

## 需保存的證據

- **DCSync 的完整 4662 事件**（SubjectAccount、Properties GUID、AccessMask）
- **AS-REP/Kerberoasting 的 4768/4769 原始 EventData**（PreAuthType、TicketEncryptionType 實際值）
- **Silver Ticket 的 SRV-FILE 4624 記錄**（TargetUserName、IpAddress、LogonType）
- **RBCD 5136 事件**（ObjectDN、AttributeValue 二進位資料）
- **PetitPotam 的 MDE DeviceNetworkEvents**（DeviceName=DC01、RemoteIP、RemotePort=445）
- **GPO 修改的 SYSVOL 檔案**（ScheduledTasks.xml、scripts.ini 原始內容）
- **觸發帳號前後 24 小時的完整 4624/4688 活動**

---

## 已知誤判（Known False Positives）

| 誤判來源 | 涉及 Stage | 處置 |
|---|---|---|
| AD 管理工具（ADUC/RSAT）日常操作 | Stage 1 | 建立授權管理帳號白名單 |
| Azure AD Connect 同步帳號 | Stage 1、5 | 白名單同步帳號，AccessMask 0x100 事件例外 |
| 監控代理程式規律 LDAP 查詢 | Stage 1 行為層 | 白名單服務帳號，行為層規則優先排除機器帳號 |
| 合法服務帳號關閉預先驗證（業務需求） | Stage 2 | 建立已知 DoesNotRequirePreAuth 帳號清單 |
| 合法 IT 管理員使用 runas 跨帳號 Kerberos 存取 | Stage 6d | 建立已知管理員來源 IP 白名單 |
| 合法委派設定變更（由授權管理員執行） | Stage 7a | 白名單委派管理帳號 |
| 合法 GPO 管理（Domain Admin 執行） | Stage 8 | 白名單 GPO 管理帳號清單 |

---

## 快速參考

| 階段 | 優先級 | 第一動作 | 關鍵證據 |
|---|---|---|---|
| 1（LDAP 偵察） | 中 | 確認帳號性質，查詢後續 Stage 2/3 | ObjectType 種類數、SubjectAccount |
| 2（AS-REP Roasting） | 高 | 重設被索取帳號密碼，清點 PreAuth=False 帳號 | PreAuthType、TargetUser、SrcIp |
| 3（Kerberoasting） | 高 | 確認服務帳號密碼強度，高權限帳號立即重設 | ServiceName、RoastedNoLogon |
| 4b（gMSA） | 中高 | 確認授權讀取清單，關聯其他 Stage | Subject、ObjectName |
| 5（DCSync） | **最高** | 停用帳號、krbtgt 輪替兩次 | Properties GUID、SubjectAccount |
| 6a（Golden Ticket 嘗試） | 高 | 確認環境 PAC 驗證設定，後續偵察 | Status 0x12、SrcIp |
| 6b（Silver Ticket） | **最高** | 輪替 SRV-FILE 機器帳號密碼 | SRV-FILE 4624 vs DC 4769 矛盾 |
| 6d（Pass-the-Ticket） | 高 | 確認橫向存取範圍，關聯 DCSync | IpAddress、多主機 TargetHosts |
| 7a（RBCD 寫入） | 高 | 清除異常委派屬性，溯源寫入帳號 | ObjectDN、AttributeValue |
| 7b（Unconstrained Coercion） | **最高** | 移除 TrustedForDelegation，輪替 DC 機器帳號密碼 | DC 對外 SMB、NTLMv2 hash |
| 8（ACL/GPO 持久化） | **最高** | 移除異常 ACE/SYSVOL 惡意檔案 | nTSecurityDescriptor 變更、SYSVOL 內容 |
