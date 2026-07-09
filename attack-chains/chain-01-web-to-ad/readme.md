# chain-01-web-to-ad

## 項目概述 

主要從DMZ webshell到AD域控權限的完整攻擊鏈。

## 攻擊流程

DMZ webshell → 憑證獲取 → LDAP 大規模枚舉 → kerberoast → WriteDACL → DCSync

## 項目成果

|內容                               |狀態   |說明|KQL 規則|
| ------------- |:-------------:|:-------------:|:-------------|
|stage 1 : T1190 - Webshell 上傳    | ✓成功 | Webshell 上傳到 DMZ-web |✗|
|stage 2 : T1505.003 - IIS 命令執行  | ✓成功 | w3wp.exe 運行系統命令|IIS - w3wp - Spawning Suspicious Child Process (T1059.003)|
|stage 3 : T1547.014 Webshell 持久化 | ✓成功 | webshell 部署|✗|
|stage 4 : T1016/T1049 - 網路發現    | ✓成功 | 發現DC+Domain |IIS - w3wp - Network Discovery Command Execution (T1016)|
|stage 5 : T1552.001 - 憑證獲取      | ✓成功 | 從腳本找到Jenny明碼憑證|IIS - w3wp - Credential Scanning via findstr (T1552.001)|
|stage 6 : T1134.001 - 權限提升      | ✗失敗 | GodPotato被MDE攔截|✗|
|stage 7 : T1087.002/T1018 LDAP枚舉  | ✓成功 | 發現用戶跟SPN|AD - LDAP - Enumeration Tool Execution (T1087.002)|
|stage 8 : T1558.003 - Kerberoasting| ✓成功 | 獲得3個RC4加密的TGS Hash|AD - KDC - RC4 Encrypted TGS Request Detected (T1558.003)<br>AD - KDC - Kerberoasting TGS Requests (T1558.003)|
|stage 9 :  T1222 - WriteDACL    |✓成功| 利用 Backup-Admins 的過度授權，賦予 svc_backup DS-Replication 複寫權限|AD - DomainObject - WRITE_DAC Permission Modification (T1222)|
|stage 10 : T1003.006 - DCSync      |✓成功|利用svc_backup做DCSync|AD - DomainObject - Directory Replication by Non-DC Account (T1003.006)|


## 未覆蓋階段

以下階段目前無 KQL 規則:

**Stage 1 / Stage 3(T1190 Webshell 上傳、T1547.014 持久化)**

缺口:目前 lab 未啟用 Sysmon file monitoring,因此無法產生可驗證的偵測規則。若補齊環境,構想邏輯如下:

- **Stage 1(初次落地)**:以 Sysmon EventID 11(FileCreate)監控 web root 路徑,篩選副檔名為 `.aspx/.ashx/.asp` 且建立程序為 `w3wp.exe`——web 伺服器自己寫入可執行網頁本身就是異常行為,訊號比對 IIS log 更明確。若無 Sysmon,退而求其次可用 W3C IIS Log,比對「已知合法部署清單」外出現的新路徑請求。
- **Stage 3(持久化)**:沿用同一組資料來源 ,差異在於關注「同一來源短時間內對多個不同路徑寫入」的模式(備援 webshell 特徵),或監控 `web.config` 異動(常見於持久化搭配設定變更)。

**Stage 6(T1134.001 - GodPotato 被 MDE 攔截)**

GodPotato 被 MDE 成功攔截,提權未成功:若 MDE alert 已同步進 Sentinel 的 SecurityAlert 表,可針對alert分類建關聯規則,確保 SOC 端不用盯著 MDE console 也能看見。


## Stage 9 補充說明:自我提權嘗試與實際執行落差

**前置條件**:`svc_backup` 為 `Backup-Admins` 群組成員,該群組對 Domain Root 具有 WriteDACL 權限
（模擬企業備份帳號過度授權的常見錯誤配置）。

**原始設計**:利用 `svc_backup` 竊取的憑證,透過 `impacket-dacledit` 自行修改 Domain Root
ACL,授予自己 DCSync 複寫權——完整展示「無需人工介入的自動化提權」。

**實際執行**:`impacket-dacledit` 執行失敗,錯誤訊息指向 LDAP 連線層級被拒絕，而非 AD 物件權限層級的拒絕。這代表無法排除
`Backup-Admins` 對 Domain Root 確實具有 WriteDACL 權限的可能性——工具連線都沒能成功建立，
自然也就無從驗證權限本身是否有效。為了讓後續 Stage 10 DCSync 能夠展示，改由 `labadmin`
（網域管理員身份）直接在 DC01 上以 PowerShell 手動授予 `svc_backup` 複寫權。

**影響範圍**:WriteDACL 偵測規則本身仍為已驗證（4662 事件確實由此操作產生，規則邏輯不
受執行者身份影響）；但「攻陷帳號利用既有權限自我提權」這個攻擊能力**未完整驗證**，Stage
9 到 Stage 10 之間的因果鏈存在一個以人工手動補齊的斷點，非攻擊者自主完成。
