# chain-03-kerberos-lotl

## 項目概述

Kerberos 票證濫用與 LOTL 三層偵測深化鏈。前兩條攻擊鏈證明「攻擊可被偵測」，本鏈聚焦「偵測的縱深」——每項技術設計三層偵測（工具簽章層 / API 原語層 / 行為結果層），證明當任一層被繞過時仍有下一層觸發。

本鏈同時覆蓋三個實務延伸面向：gMSA 密碼 Blob 非授權讀取（LSASS 被攔截後的替代憑證竊取路徑）、Pass-the-Ticket 橫向移動（以 Silver Ticket 存取 SRV-FILE；多主機偵測規則因 lab 規模無法驗證，已移除）、Unconstrained Delegation（委派濫用的第二條攻擊路徑）。

## 攻擊流程

低速 LDAP 偵察 → AS-REP Roasting → Kerberoasting → LSASS Blocked / gMSA 非授權讀取 → DCSync → 票證鍛造（Golden/Silver/Diamond/Sapphire）+ Pass-the-Ticket 橫向 → RBCD + Unconstrained Delegation 委派濫用 → ACL/GPO 持久化

## 攻擊鏈流程圖

```mermaid
flowchart TD
    S1["Stage 1 · T1087.002<br/>低速 LDAP 偵察"]:::verified
    S2["Stage 2 · T1558.004<br/>AS-REP Roasting"]:::verified
    S3["Stage 3 · T1558.003<br/>Kerberoasting"]:::verified
    S4a["Stage 4a · T1003.001<br/>LSASS (MDE Blocked)"]:::blocked
    S4b["Stage 4b · T1552.001<br/>gMSA 密碼 Blob 非授權讀取"]:::partial
    S5["Stage 5 · T1003.006<br/>DCSync"]:::verified
    S6a["Stage 6a · T1558.001<br/>Golden Ticket (Server 2025 Blocked)"]:::blocked
    S6b["Stage 6b · T1558.002<br/>Silver Ticket"]:::verified
    S6c["Stage 6c · T1558<br/>Diamond/Sapphire (Server 2025 Blocked)"]:::blocked
    S6d["Stage 6d · T1550.003<br/>Pass-the-Ticket 橫向移動"]:::partial
    S7a["Stage 7a · T1134<br/>RBCD 委派濫用"]:::partial
    S7b["Stage 7b · T1187<br/>Unconstrained Delegation + Coercion"]:::verified
    S8["Stage 8 · T1484.001/T1222<br/>ACL/GPO 持久化"]:::partial

    S1 --> S2 --> S3 --> S4a
    S3 --> S4b
    S4a --> S5
    S4b --> S5
    S5 --> S6a
    S5 --> S6b
    S5 --> S6c
    S6a --> S6d
    S6b --> S6d
    S6d --> S7a --> S7b --> S8

    classDef verified fill:#2ea04333,stroke:#2ea043,color:#1a7431
    classDef partial fill:#e3b34122,stroke:#e3b341,color:#7d6514
    classDef conceptual fill:#8b8b8b22,stroke:#8b8b8b,stroke-dasharray:4 3,color:#5a5a5a
    classDef blocked fill:#1f6feb22,stroke:#1f6feb,color:#1554b3
```

**圖例:**
- 🟢 **已驗證**（綠色）— 攻擊執行 + Sentinel 命中 KQL 規則
- 🟡 **部分**（黃色）— 攻擊成功但偵測有限制或 Sentinel 未完整驗證
- 🔘 **概念設計**（灰色虛線）— 攻擊成功或邏輯設計完成，偵測待補
- 🔵 **被攔截**（藍色）— EDR 或環境防護阻擋攻擊

---

## 三層偵測方法論

| 層級 | 偵測依據 | 韌性 | 被繞過條件 |
|---|---|---|---|
| 工具簽章層 | 已知攻擊工具命令列特徵 | 最低 | 換工具、改名、LOTL |
| 原語層 | 協定/API 本質行為（4768/4769/4662/5136） | 中 | 低速、AES 降級規避 |
| 行為結果層 | 跨事件因果落差（DCSync 後接票證活動、Silver Ticket 服務有登入但 DC 無索票） | 最高 | 極難規避（需消除因果痕跡） |

---

## 環境校準紀錄

| 校準項目 | 初始假設 | 實測結果 | 修正 |
|---|---|---|---|
| Stage 1 ObjectType 門檻 | DistinctObjectTypes >= 5 | 完整枚舉只產生 3 種 | 改為 >= 3 |
| Stage 2/3 加密類型 | TicketEncryptionType == "0x17" RC4 | DC 強制 AES 回 0x12，RC4 請求報 KDC_ERR_ETYPE_NOSUPP | 移除 enctype 限定 |
| Stage 2/3 欄位解析 | 直接用欄位名（PreAuthType 等） | 4768/4769 欄位未被 DCR 原生解析，藏在 EventData XML | 全面改用 extract() |
| Stage 5 AccessMask | 誤用 0x40000（這是 WRITE_DAC 的值） | DCSync 為 0x100（Control Access，擴充權限的標準值），環境實測確認 | 修正 |
| Stage 6a Golden Ticket | 偽造 TGT 可用 | Windows Server 2025 多層 PAC 驗證，六種方式均被拒 | 標記環境限制 |
| Stage 7a 5136 稽核 | RBCD 寫入觸發 5136 | DC 本機不產生 5136，impacket LDAP channel 問題 | 改用 DeviceProcessEvents，待驗證 |
| Stage 8 GPO 路徑 | 5136 偵測 GPO 修改（路徑A） | 攻擊走路徑B（直接寫 SYSVOL），5136 不產生 | 改用 DeviceFileEvents |
| Stage 6a 票證鍛造規則 | TGS 無 AS-REQ 因果落差、失敗狀態碼 0x12 可偵測 Golden Ticket | TGT 快取 10 小時使因果落差在正常流量下普遍存在；0x12 實為帳號停用／鎖定（TGT 撤銷是 0x14） | 2026-11 審查移除 |
| Stage 8 GPO 下游執行 | Windows 11 CSE 觸發條件嚴格 | 較可能是路徑B只寫 SYSVOL，AD 端 gPCMachineExtensionNames／versionNumber 未更新，用戶端不處理新 CSE | 待改用 GPMC／SharpGPOAbuse 重測 |

---

## 項目成果

| Stage | 技術 | 狀態 | 說明 | KQL 規則 |
|---|---|---|---|---|
| Stage 1 | T1087.002 低速 LDAP 偵察 | ✅ 驗證 | DirectorySearcher LOTL；門檻校準 >=3；AccessMask 0x10 | AD - Recon - Anomalous LDAP Object Enumeration<br>AD - Recon - Low-and-Slow LDAP Enumeration |
| Stage 2 | T1558.004 AS-REP Roasting | ✅ 驗證 | 3 個 svc-legacy 帳號；EventData extract()；DC 回 AES256(0x12) | AD - KDC - AS-REP Roasting Pre-Auth Disabled<br>AD - KDC - AS-REP Roasting Bulk Harvesting |
| Stage 3 | T1558.003 Kerberoasting | ✅ 驗證 | AES hash 得手；Multi-SPN 聚合（不同 SPN 數）；SPNSet 內容判斷 | AD - KDC - Kerberoasting Multi-SPN Harvesting |
| Stage 4a | T1003.001 LSASS | 🔵 攔截 | comsvcs MiniDump 被 MDE HackTool:Win32/DumpLsass.H 攔截 | Endpoint - LSASS - Suspicious Process Access（待驗證）<br>Endpoint - LSASS - Credential Dump via comsvcs MiniDump（待驗證） |
| Stage 4b | T1552.001 gMSA 密碼 Blob | ⚠️ 部分 | netexec --gmsa Alice 非授權讀取被拒；DC01 產生 4662 35 筆；Sentinel KQL 待補跑 | AD - gMSA - Unauthorized ManagedPassword Attribute Access（待驗證） |
| Stage 5 | T1003.006 DCSync | ✅ 驗證 | svc_backup 執行；AccessMask 0x100 確認；行為層關聯 4769 | AD - DomainObject - Directory Replication by Non-DC Account<br>AD - DCSync Followed by Anomalous KRBTGT Activity |
| Stage 6a | T1558.001 Golden Ticket | 🔵 環境限制 | Windows Server 2025 PAC 驗證；六種方式均被 KDC_ERR_TGT_REVOKED 拒絕 | —（3 條規則於 2026-11 審查移除，原因見 README） |
| Stage 6b | T1558.002 Silver Ticket | ✅ 驗證 | cifs/SRV-FILE；存取 C$/FinanceShare/HRShare；SRV-FILE 4624 有但 DC 4769 無 | AD - Kerberos - Silver Ticket Service Access Without DC Log |
| Stage 6c | T1558 Diamond/Sapphire | 🔵 環境限制 | Windows Server 2025 PAC 驗證同樣擋住 Diamond | —（PAC Privilege Anomaly 規則已移除） |
| Stage 6d | T1550.003 Pass-the-Ticket | ⚠️ 部分 | Silver Ticket 存取 C$/FinanceShare/HRShare 成功；遠端執行受 cifs SPN 限制 | —（多主機規則已移除：lab 僅一台檔案伺服器，且邏輯無法區分正常使用） |
| Stage 7a | T1134 RBCD | ⚠️ 部分 | msDS-AllowedToActOnBehalfOfOtherIdentity 寫入成功；S4U 被 Server 2025 擋；5136 不產生；改以 DeviceProcessEvents 工具簽章層偵測 | AD - Delegation - RBCD Attribute Modification（待驗證：攻擊從 Kali 發起，需改從 Windows 端點執行一次）|
| Stage 7b | T1187 Unconstrained Delegation | ✅ 驗證 | PetitPotam Attack worked!；Responder 捕獲 DC01$ NTLMv2 hash；MDE DeviceNetworkEvents 驗證 | AD - Coerced Authentication - DC Outbound SMB |
| Stage 8 | T1484.001/T1222 ACL/GPO | ⚠️ 部分 | ACL 寫入 5136 Sentinel 通過；GPO SYSVOL 寫入成功；下游執行未觸發 | AD - ACL - GenericAll DACL Grant on Container<br>AD - GPO - Unauthorized Group Policy Modification（待驗證）<br>AD - GPO Abuse to Endpoint Execution（待驗證） |

---

## KQL 規則總覽

Chain 3 共 15 條規則：9 條已驗證、6 條待驗證（另含與 Chain 1 共用的 DCSync 規則）。

### TA0007-discovery（2 條）
| 規則 | 層級 | 狀態 |
|---|---|---|
| AD - Recon - Anomalous LDAP Object Enumeration (T1087.002) | 原語層 | ✅ |
| AD - Recon - Low-and-Slow LDAP Enumeration (T1087.002) | 行為層 | ✅ 概念驗證 |

### TA0006-credential-access（9 條 + 共用 DCSync）
| 規則 | 層級 | 狀態 |
|---|---|---|
| AD - KDC - AS-REP Roasting Pre-Auth Disabled (T1558.004) | 原語層 | ✅ |
| AD - KDC - AS-REP Roasting Bulk Harvesting (T1558.004) | 行為層 | ✅ |
| AD - KDC - Kerberoasting Multi-SPN Harvesting (T1558.003) | 原語層升級 | ✅ |
| Endpoint - LSASS - Suspicious Process Access (T1003.001) | 原語層(MDE) | 🟡 待驗證 |
| Endpoint - LSASS - Credential Dump via comsvcs MiniDump (T1003.001) | 工具簽章層(MDE) | 🟡 待驗證 |
| AD - DomainObject - Directory Replication by Non-DC Account (T1003.006) | 原語層 | ✅（與 Chain 1 共用） |
| AD - DCSync Followed by Anomalous KRBTGT Activity (T1003.006) | 行為層 | ✅ |
| AD - Kerberos - Silver Ticket Service Access Without DC Log (T1558.002) | 行為層 | ✅ |
| AD - gMSA - Unauthorized ManagedPassword Attribute Access (T1552.001) | 原語層 | 🟡 待驗證（DC 本機已確認，Sentinel 待補跑） |
| AD - Coerced Authentication - DC Outbound SMB (T1187) | 行為層 | ✅ |

### TA0004-Privilege-Escalation（3 條）
| 規則 | 層級 | 狀態 |
|---|---|---|
| AD - Delegation - RBCD Attribute Modification (T1134) | 工具簽章層 | 🟡 待驗證（需從 Windows 端點執行） |
| AD - GPO - Unauthorized Group Policy Modification (T1484.001) | 原語層(路徑B) | 🟡 待驗證（補跑 DeviceFileEvents） |
| AD - GPO Abuse to Endpoint Execution (T1484.001) | 行為層 | 🟡 待驗證（下游執行未觸發） |

### TA0112-Defense-Impairment（1 條）
| 規則 | 層級 | 狀態 |
|---|---|---|
| AD - ACL - GenericAll DACL Grant on Container (T1222) | 原語層 | ✅ 本機操作驗證 |

### 2026-11 審查移除（7 條）
| 規則 | 原因 |
|---|---|
| AD - KDC - Kerberoast Ticket Without Logon | 服務帳號本來就很少產生 4624，正常情況也會持續命中 |
| Endpoint - DPAPI - Masterkey File Access | DeviceFileEvents 不記錄檔案讀取，抓不到存取 |
| AD - Kerberos - Golden Ticket TGS Without AS-REQ | TGT 快取使因果落差在正常流量下普遍存在；攻擊被擋無法驗證 |
| AD - Kerberos - Anomalous Ticket Lifetime | 4769 事件本身沒有 StartTime／EndTime 欄位 |
| AD - Kerberos - Golden Ticket Attempt Rejected | 狀態碼 0x12 是帳號停用／鎖定，不是 TGT 撤銷（0x14）；事件也選錯 |
| AD - Kerberos - PAC Privilege Anomaly Diamond Sapphire | 帳號格式不一致 join 永遠配不到；兩事件無因果關係 |
| AD - Pass-the-Ticket - Forged TGT Lateral Movement Behavioral | 邏輯無法區分正常使用者；lab 規模無法驗證 |

---

## 環境限制說明

**Stage 6a/6c Golden/Diamond/Sapphire — 🔵 Server 2025 PAC 驗證**
Windows Server 2025 開啟多層 Kerberos PAC 驗證，impacket v0.14.0 六種方式均被 KDC_ERR_TGT_REVOKED 拒絕。失敗不留 Security Event。Silver Ticket 仍有效，證明服務主機保護弱於 DC。原本針對這三種票證設計的規則都無法在此環境驗證，審查後移除。

**Stage 4a LSASS — 🔵 MDE 攔截**
comsvcs MiniDump 被 MDE（HackTool:Win32/DumpLsass.H）在 rundll32 層級阻止。MDE 的工具簽章層在這裡有效，與 Stage 1 LOTL 讓工具簽章層失效形成對比。MDE 阻擋通常發生在程序建立之後，兩條 LSASS 規則可先用 Stage 4a 當時的遙測驗證。

**Stage 7a S4U2Self — 🔵 Server 2025 Protocol Transition 限制**
RBCD 屬性寫入成功，但 S4U2Self 被 Server 2025 的 Protocol Transition 限制擋住。5136 DC 本機不產生，impacket LDAP channel 不觸發稽核事件。偵測改用 DeviceProcessEvents 工具簽章層，偵測 rbcd.py / PowerView Set-DomainRBCD / Set-ADComputer -PrincipalsAllowedToDelegateToAccount 命令列特徵；因攻擊從 Kali 直接發起 LDAP，Windows 端點無對應程序記錄，需改從 Windows 端點執行一次驗證。

**Stage 8 GPO 下游執行 — 🟡 待驗證**
SYSVOL 寫入成功（路徑B），但 Immediate Task 和 Startup Script 重開機後均未執行。較可能的原因：路徑B 只寫 SYSVOL，AD 端 groupPolicyContainer 物件的 gPCMachineExtensionNames 與 versionNumber 沒有同步更新，用戶端判斷 GPO 未變更、不會處理新的 CSE。驗證時改用會同時更新 AD 屬性與 SYSVOL 的方式（GPMC、SharpGPOAbuse／pyGPOAbuse）。
