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
| Chain 3	| Kerberos 票證濫用 → 憑證竊取 → 票證鍛造 → 委派濫用 → 持久化 |	🔨 進行中|

## 偵測規則 (Detection Rules)

📋 **完整規則清單與驗證狀態**

完整的 MITRE ATT&CK 覆蓋率矩陣（互動版）：<br>
👉 **https://dabbychiu.github.io/Purple-Team-Detection-Lab/** <br>
黃色代表已有偵測覆蓋，點擊任一技術可展開對應的 Sentinel KQL規則。
