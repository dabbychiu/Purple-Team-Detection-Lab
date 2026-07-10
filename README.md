# Purple-Team-Detection-Lab

## Overview

這是一個以「藍隊偵測規則設計」為核心目的的實驗室。透過在真實 Azure 環境中完整執行攻擊鏈,產生真實、可觀測的攻擊遙測資料,讓每一條 Microsoft Sentinel 偵測規則都經過實際攻擊流程驗證,而非憑空推測攻擊行為。攻擊情境的規劃採 AI 輔助,環境建置、攻擊執行與偵測驗證均為手動實作。

## 環境架構
模擬小型企業網路，包含對外服務、內網主機、網域控制器三層，並以 NSG/ASG 做網段隔離：
| 主機|IP |角色|
|---|---|---|
|DMZ-Web (IIS)|10.0.2.4|對外服務|
|WIN11-EDR|10.0.4.4|內網終端|
|DC01|10.0.3.4|網域控制器（corp.lab）|

<img width="1276" height="770" alt="image" src="https://github.com/user-attachments/assets/38857898-3693-4f50-b383-7c427d746b24" />


日誌透過 AMA / DCR pipeline 集中送往 Microsoft Sentinel。

## 攻擊鏈總覽
| Chain | 攻擊 階段 | 對應偵測規則 |
|---|---|---|
| Chain 1 | DMZ Webshell → LDAP枚舉 → Kerberoasting → WriteDACL → DCSync | 見 `detection-coverage.md` |

## 偵測規則 (Detection Rules)

針對攻擊鏈每個階段開發並以實際流量驗證的 Microsoft Sentinel KQL 規則。

📋 **完整規則清單與驗證狀態 → [detection-coverage.md](./detections/detection-coverage.md)**
