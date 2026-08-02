# Purple-Team-Detection-Lab

## Overview

以攻擊者視角驅動偵測設計，核心為偵測規則的開發與驗證，並在真實 Azure 環境中完整執行攻擊鏈，產生真實、可觀測的攻擊遙測資料，讓每一條 Microsoft Sentinel 偵測規則都經過實際攻擊流程驗證，而非憑空推測攻擊行為。攻擊情境的規劃採 AI 輔助，環境建置、攻擊執行與偵測驗證均為手動實作。

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


## 偵測規則 (Detection Rules)

針對攻擊鏈每個階段開發並以實際流量驗證的 Microsoft Sentinel KQL 規則。

📋 **完整規則清單與驗證狀態**

完整的 MITRE ATT&CK 覆蓋率矩陣（互動版）：<br>
👉 **https://dabbychiu.github.io/Purple-Team-Detection-Lab/** <br>
黃色代表已有偵測覆蓋，點擊任一技術可展開對應的 Sentinel KQL 與 QRadar 規則連結。
