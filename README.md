# Purple-Team-Detection-Lab

## Overview

所有攻擊執行的成功與失敗、所有偵測規則的有效與侷限，都來自真實環境的驗證，不是理論推測。攻擊被 MDE 攔截、工具假設被環境推翻、規則門檻需要校準——這些都誠實記錄在文件中，而非只展示成功的結果。

以攻擊者視角驅動偵測設計，在真實 Azure 環境中完整執行攻擊鏈，產生可觀測的攻擊遙測資料，以此為基礎開發與驗證 Microsoft Sentinel 偵測規則。從 Chain 1/2 的攻擊執行層驗證，到 Chain 3 的偵測工程層校準（三層偵測方法論：工具層/原語層/行為層、門檻與欄位的真實環境校準）。

攻擊情境的規劃採 AI 輔助，環境建置、攻擊執行與偵測驗證均為手動實作。

## 環境架構
模擬小型企業網路，包含對外服務、內網終端、網域控制器、檔案伺服器，並以 NSG/ASG 做網段隔離。日誌透過 AMA / DCR pipeline 集中送往 Microsoft Sentinel，MDE 遙測透過 Microsoft Defender for Endpoint connector 整合。
| 主機|IP |角色|
|---|---|---|
|DMZ-Web (IIS)|10.0.2.4|對外服務|
|EMPLOYEE01|10.0.4.4|內網終端|
|DC01|10.0.3.4|網域控制器（corp.lab）|
| SRV-FILE | 10.0.3.5 | 檔案伺服器（SMB 共享） |

<img width="1276" height="770" alt="Image" src="https://github.com/user-attachments/assets/c9bff438-615a-44c4-b77c-3ebe456c6a5e" />
日誌透過 AMA / DCR pipeline 集中送往 Microsoft Sentinel。

## 攻擊鏈總覽
| Chain | 攻擊情境 | 狀態 |
|-------|---------|------|
| Chain 1 | DMZ Webshell → LDAP 枚舉 → Kerberoasting → WriteDACL → DCSync | ✅ 完成 |
| Chain 2 | ClickFix 釣魚 → Sliver C2 → ADCS ESC1 → 橫向 SRV-FILE → 勒索 | ✅ 完成 |
| Chain 3	| Kerberos 票證濫用 → 憑證竊取 → 票證鍛造 → 委派濫用 → 持久化 |	 ✅ 完成|

### chain 1 特色：Web-to-AD 完整接管鏈

從對外 IIS webshell 一路打到 DCSync，展示純 AD 攻擊路徑上每個階段如何落在可觀測的日誌事件。

|攻擊階段	|偵測依據	|備註|
|---------|---------|---|
|Kerberoasting	|4769 TGS 請求|	服務帳號索票模式|
|WriteDACL	|4662 / 5136 DACL 修改 |	ACL 濫用寫入|
|DCSync	|4662 replication GUID (DS-Replication-Get-Changes)	|網域接管指標|

**誠實記錄的斷點： impacket-dacledit 透過 svc_backup 自我提權在 LDAP 層失敗，<br>
WriteDACL → DCSync 的因果鏈改由 labadmin 手動完成。<br>**

### chain 2 特色：人為入口 + C2 + 憑證濫用

ClickFix 社交工程入口，經 Sliver C2 與 LOLBins，到 ADCS ESC1 憑證濫用與橫向勒索。

偵測面因此從純 AD 事件擴展到 EDR 遙測(MDE)、C2 行為與憑證簽發事件，<br>
13 條 Sentinel KQL 規則全部驗證。<br>

|攻擊階段	|偵測依據	|備註|
|---------|---------|---|
|ClickFix / Sliver C2	|MDE 程序遙測 + LOLBin 命令列	|跨 endpoint 與 AD 日誌關聯|
|ADCS ESC1	|4886 / 4887 憑證請求與簽發|	範本錯誤配置濫用|
|勒索收尾	|rclone 外傳 + VSS 刪除	|資料外洩與破壞|

誠實記錄的斷點： MDE AMSI 攔截所有 PowerShell shellcode loader 與 demon.exe 下載;<br>
繞過方式為管理員手動設定 Defender 排除路徑(C:\Users\Public)，文件中標示為執行斷點，而非攻擊者自主達成。

### Chain 3 特色：三層偵測縱深
Chain 3 在既有的「攻擊得手 → 偵測驗證」模式上，進一步探索同一技術的偵測深度：
|層級	|偵測依據	|分級|	Chain 3 範例|
|-----|---------|-----------------|-----|
|工具簽章層|	已知攻擊工具命令列特徵	|最低	|SharpHound 規則在 LOTL 面前失效|
|原語層	|協定/API 本質行為（4662/4768/4769）	|中|	4662 ObjectType 枚舉、PreAuthType=0|
|行為層|	跨事件因果落差	|最高	|索票無登入、TGS 無 AS-REQ、DCSync 後接票證活動|

Chain 3 的核心主題——每一個「規則寫出來」和「規則真的有效」之間的差距，都在真實遙測上被驗證：<br>
ObjectType 門檻從 >=5 校準到 >=3（完整枚舉只產生 3 種）<br>
RC4 假設在 Server 2025 AES 強制環境失效（KDC_ERR_ETYPE_NOSUPP）<br>
4768/4769 欄位未被 DCR 原生解析（需 extract() 從 EventData XML 取值）<br>
impacket LDAP channel 不觸發 5136 稽核（即使 SACL 已設）<br>

## 偵測工程校準（Detection Engineering Calibration）

每條規則在真實遙測上被驗證前都帶著假設，以下是本 lab 中被推翻的三個典型：

| 假設 | 真實結果 | 修正 |
|---|---|---|
| ObjectType 門檻 >=5 | 完整 AD 枚舉只產生 3 種（user/group/computer） | 改為 >=3 |
| TicketEncryptionType == "0x17"（RC4） | Server 2025 DC 強制 AES，RC4 請求直接報 KDC_ERR_ETYPE_NOSUPP | 移除 enctype 限定，改看行為 |
| 4768/4769 欄位可直接用欄位名查詢 | Sentinel DCR 未原生解析，欄位藏在 EventData XML | 全面改用 extract() |

這個校準過程記錄在 [`attack-chains/chain-03-kerberos-lotl/detection-design.md`]


## 偵測規則 (Detection Rules)

📋 **完整規則清單與驗證狀態**

完整的 MITRE ATT&CK 覆蓋率矩陣（互動版）：<br>
👉 **https://dabbychiu.github.io/Purple-Team-Detection-Lab/** <br>
黃色代表已有偵測覆蓋，點擊任一技術可展開對應的 Sentinel KQL規則。
