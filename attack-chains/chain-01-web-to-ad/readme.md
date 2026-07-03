chain 1 : DMZ to AD
AD滲透攻擊 + sentinel 偵測規則

** 項目概述 ** 
這是一個紫隊實驗室，主要一條從DMZ webshell到AD域控權限的完整攻擊鏈，主要檢測對應的sentinel的規則。

攻擊流程:

DMZ webshell → 憑證獲取 → LDAP 大規模枚舉 → kerberoast → WriteDACL → DCSync

** 項目成果 **
|內容                               |狀態   |說明|
|stage 1 : T1190 - Webshell 上傳    | ✓成功 | Webshell 上傳到 DMZ-web |
|stage 2 : T1505.003 - IIS 命令執行  | ✓成功 | w3wp.exe 運行系統命令|
|stage 3 : T1547.014 Webshell 持久化 | ✓成功 | webshell 部署|
|stage 4 : T1016/T1049 - 網路發現    | ✓成功 | 發現DC+Domain |
|stage 5 : T1552.001 - 憑證獲取      | ✓成功 | 從腳本找到Jenny明碼憑證|
|stage 6 : T1134.001 - 權限提升      | ✗失敗 | GodPotato被MDE攔截|
|stage 7 : T1087.002/T1018 LDAP枚舉  | ✓成功 | 發現用戶跟SPN|
|stage 8 : T1558.003 - Kerberoasting| ✓成功 | 獲得3個RC4加密的TGS Hash|
|stage 9 : T1484.002 - WriteDACL    |[]測試中| |
|stage 10 : T1003.006 - DCSync      |[]測試中||
|KQL 偵測規則 | ||


