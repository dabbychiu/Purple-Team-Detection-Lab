# Detection Coverage

## 覆蓋率總覽

| 項目 | 數量 |
|------|------|
| 攻擊鏈 | 1 |
| 偵測規則 | 8 |
| 已驗證規則 | 8 |
| 覆蓋 MITRE Tactic | 4 |
| 覆蓋 MITRE Technique | 7 |

---

## MITRE Tactic 覆蓋

| Tactic | ID | 規則數 | 覆蓋 Chain |
|--------|----|--------|-----------|
| Execution | TA0002 | 1 | Chain 1 |
| Privilege Escalation | TA0004 | 1 | Chain 1 |
| Credential Access | TA0006 | 4 | Chain 1 |
| Discovery | TA0007 | 2 | Chain 1 |

---

## 完整規則清單

| 規則名稱 | Tactic | Technique | Chain | Stage | EventID | 嚴重性 | 狀態 |
|---------|--------|-----------|-------|-------|---------|--------|------|
| IIS - w3wp - Spawning Suspicious Child Process | Execution | T1059.003 | Chain 1 | Stage 2 | 4688 | HIGH | ✅ 已驗證 |
| IIS - w3wp - Network Discovery Command Execution | Discovery | T1016 | Chain 1 | Stage 4 | 4688 | MEDIUM | ✅ 已驗證 |
| IIS - w3wp - Credential Scanning via findstr | Credential Access | T1552.001 | Chain 1 | Stage 5 | 4688 | MEDIUM | ✅ 已驗證 |
| AD - LDAP - Enumeration Tool Execution | Discovery | T1087.002 | Chain 1 | Stage 7 | 4688 | MEDIUM | ✅ 已驗證 |
| AD - KDC - RC4 Encrypted TGS Request Detected | Credential Access | T1558.003 | Chain 1 | Stage 8 | 4769 | MEDIUM | ✅ 已驗證 |
| AD - KDC - Kerberoasting TGS Requests  | Credential Access | T1558.003 | Chain 1 | Stage 8 | 4769 | HIGH | ✅ 已驗證 |
| AD - DomainObject - WRITE_DAC Permission Modification | Privilege Escalation | T1222 | Chain 1 | Stage 9 | 4662 | CRITICAL | ✅ 已驗證 |
| AD - DomainObject - Directory Replication by Non-DC Account | Credential Access | T1003.006 | Chain 1 | Stage 10 | 4662 | CRITICAL | ✅ 已驗證 |

---

## 驗證說明

標記為 ✅ 已驗證 的規則代表：

- 在 Azure 實驗室中實際執行了對應的攻擊手法
- Microsoft Sentinel 中確認產生了對應的 Log 事件
- KQL 查詢可成功命中該事件

所有規則皆為原型驗證邏輯，部署正式環境前需依基線調整誤報閾值。
