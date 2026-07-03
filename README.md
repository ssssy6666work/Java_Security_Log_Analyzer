# Java Security Log Analyzer｜Java 8 資安日誌異常偵測器

這是一個使用 **Java 8** 開發的防禦型資安作品集專案，用來分析安全事件日誌，並偵測常見的可疑行為，例如：

- 暴力破解登入 Brute Force Login
- SQL Injection 可疑字串
- XSS 可疑字串
- Path Traversal 可疑路徑存取
- sqlmap、nmap、nikto 等掃描工具特徵

這個專案的目的不是做攻擊工具，而是模擬資安維運在日常工作中，如何從 log 裡面找出可疑事件，並整理成報告。

---

## 1. 專案定位

這是一個 **防禦型資安日誌分析工具**。

它會讀取一份安全事件日誌，例如：

```text
2026-07-04T10:00:00Z INFO 203.0.113.10 alice LOGIN_FAILED Invalid password
2026-07-04T10:08:00Z WARN 198.51.100.23 guest HTTP_REQUEST GET /products?id=1' OR '1'='1 Mozilla/5.0
2026-07-04T10:10:00Z WARN 192.0.2.80 guest HTTP_REQUEST GET /wp-login.php sqlmap/1.7
```

然後分析裡面是否有可疑行為，最後輸出 Markdown 或 JSON 報告。

簡單來說，流程是：

```text
安全日誌檔案
    ↓
LogParser 解析 log
    ↓
LogEntry 轉成 Java 物件
    ↓
RuleEngine 執行偵測規則
    ↓
BruteForceRule / InjectionPatternRule / SuspiciousToolRule
    ↓
DetectionResult 儲存偵測結果
    ↓
ReportFormatter 產生 Markdown 或 JSON 報告
```

---

## 2. 專案特色

- 使用 Java 8，符合當初學習基礎 Java 的版本
- 使用 Maven 管理編譯、測試與打包
- 不依賴 Spring Boot 等大型框架，程式邏輯清楚
- 使用 CLI 指令列方式執行，接近實務中的工具型程式
- 使用 Rule Engine 架構，方便擴充新的資安偵測規則
- 支援 Markdown 報告，適合人閱讀
- 支援 JSON 報告，適合後續串接系統或前端 Dashboard
- 內建範例安全日誌，可以直接執行測試
- 內建 JUnit 單元測試
- 內建 GitHub Actions，每次上傳到 GitHub 會自動跑測試

---

## 3. 目前支援的偵測規則

### 3.1 Brute Force Login Detection｜暴力破解登入偵測

偵測同一個來源 IP 是否在短時間內出現大量登入失敗。

預設條件：

- 10 分鐘內
- 同一個來源 IP
- 登入失敗 5 次以上

範例 log：

```text
2026-07-04T10:00:00Z INFO 203.0.113.10 alice LOGIN_FAILED Invalid password
2026-07-04T10:01:00Z INFO 203.0.113.10 alice LOGIN_FAILED Invalid password
2026-07-04T10:02:00Z INFO 203.0.113.10 alice LOGIN_FAILED Invalid password
2026-07-04T10:03:00Z INFO 203.0.113.10 alice LOGIN_FAILED Invalid password
2026-07-04T10:04:00Z INFO 203.0.113.10 alice LOGIN_FAILED Invalid password
```

可能代表有人在嘗試猜密碼，因此會產生 HIGH 風險告警。

---

### 3.2 Web Injection Pattern Detection｜Web Injection 可疑字串偵測

偵測 log 訊息裡是否出現常見 Web 攻擊 payload。

目前支援偵測：

- SQL Injection
- XSS
- Path Traversal
- 嘗試讀取 Linux 敏感檔案
- 嘗試執行 DROP TABLE 等危險 SQL

可疑字串範例：

```text
' OR '1'='1
UNION SELECT
<script>
../
/etc/passwd
DROP TABLE
SELECT ... FROM
```

範例 log：

```text
2026-07-04T10:08:00Z WARN 198.51.100.23 guest HTTP_REQUEST GET /products?id=1' OR '1'='1 Mozilla/5.0
```

這種內容可能是 SQL Injection 測試，因此會產生 HIGH 風險告警。

---

### 3.3 Suspicious Security Tool Signature Detection｜掃描工具特徵偵測

偵測 log 裡是否出現常見掃描工具或弱點測試工具名稱。

目前支援偵測：

- sqlmap
- nikto
- nmap
- masscan
- gobuster
- dirbuster
- wpscan

範例 log：

```text
2026-07-04T10:10:00Z WARN 192.0.2.80 guest HTTP_REQUEST GET /wp-login.php sqlmap/1.7
```

這代表可能有人使用 sqlmap 掃描網站，因此會產生 MEDIUM 風險告警。

---

## 4. 專案資料夾結構

```text
java-security-log-analyzer/
├── .github/
│   └── workflows/
│       └── maven-test.yml
├── samples/
│   └── security-events.log
├── src/
│   ├── main/
│   │   └── java/
│   │       └── com/
│   │           └── renkai/
│   │               └── securitylog/
│   │                   ├── Main.java
│   │                   ├── LogParser.java
│   │                   ├── LogEntry.java
│   │                   ├── RuleEngine.java
│   │                   ├── SecurityRule.java
│   │                   ├── BruteForceRule.java
│   │                   ├── InjectionPatternRule.java
│   │                   ├── SuspiciousToolRule.java
│   │                   ├── DetectionResult.java
│   │                   ├── ReportFormatter.java
│   │                   └── Severity.java
│   └── test/
│       └── java/
│           └── com/
│               └── renkai/
│                   └── securitylog/
│                       ├── LogParserTest.java
│                       └── RuleEngineTest.java
├── pom.xml
├── .gitignore
├── LICENSE
└── README.md
```

---

## 5. 每個資料夾與檔案的功能

### 5.1 `.github/workflows/maven-test.yml`

這是 GitHub Actions 的設定檔。

功能：

- 當程式 push 到 GitHub 的 main 分支時，自動執行測試
- 使用 JDK 8
- 執行 `mvn test`
- 如果測試成功，GitHub Actions 會顯示綠色勾勾
- 如果測試失敗，代表程式可能有錯，需要修正

這個檔案可以展現你有基本 CI/CD 概念。

CI 可以簡單理解成：

```text
每次上傳程式後，自動檢查專案有沒有壞掉。
```

---

### 5.2 `samples/security-events.log`

這是範例安全日誌。

功能：

- 提供測試資料
- 讓使用者不用自己準備 log，也可以直接執行專案
- 裡面包含登入失敗、登入成功、HTTP request、SQL Injection、XSS、掃描工具等範例事件

範例：

```text
2026-07-04T10:00:00Z INFO 203.0.113.10 alice LOGIN_FAILED Invalid password
2026-07-04T10:08:00Z WARN 198.51.100.23 guest HTTP_REQUEST GET /products?id=1' OR '1'='1 Mozilla/5.0
2026-07-04T10:10:00Z WARN 192.0.2.80 guest HTTP_REQUEST GET /wp-login.php sqlmap/1.7
```

---

### 6.1 `Main.java`｜程式的入口與總指揮

它主要負責：

1. 讀取使用者輸入的指令參數
2. 判斷是否顯示 help 說明
3. 取得要分析的 log 檔案路徑
4. 設定暴力破解偵測門檻
5. 設定時間區間
6. 設定輸出格式 markdown 或 json
7. 呼叫 `LogParser` 解析 log
8. 建立所有偵測規則
9. 呼叫 `RuleEngine` 執行分析
10. 呼叫 `ReportFormatter` 產生報告
11. 將報告印在畫面上，或輸出成檔案

可以把 `Main.java` 理解成：

```text
整個工具的總指揮。
```

支援參數：

| 參數 | 功能 | 預設值 |
|---|---|---|
| `<log-file>` | 指定要分析的 log 檔案 | 必填 |
| `--failed-threshold` | 登入失敗次數門檻 | 5 |
| `--window-minutes` | 暴力破解判斷時間區間 | 10 |
| `--format` | 報告格式，markdown 或 json | markdown |
| `--output` | 將報告輸出成檔案 | 不輸出檔案 |
| `--help` | 顯示使用說明 | 無 |

範例：

```bash
java -jar target/security-log-analyzer-1.0.0.jar samples/security-events.log --format json --output report.json
```

---

### 6.2 `LogEntry.java`｜一筆日誌資料的模型

`LogEntry.java` 代表一筆 log 事件。

例如這一行：

```text
2026-07-04T10:00:00Z INFO 203.0.113.10 alice LOGIN_FAILED Invalid password
```

會被轉成一個 `LogEntry` 物件。

欄位如下：

| 欄位 | 說明 | 範例 |
|---|---|---|
| `timestamp` | 事件時間 | `2026-07-04T10:00:00Z` |
| `level` | 日誌等級 | `INFO` |
| `sourceIp` | 來源 IP | `203.0.113.10` |
| `username` | 使用者名稱 | `alice` |
| `eventType` | 事件類型 | `LOGIN_FAILED` |
| `message` | 詳細訊息 | `Invalid password` |

它也提供 `compact()` 方法，用來把重要資訊整理成一行文字，方便放到報告的 evidence 裡。

可以把 `LogEntry.java` 理解成：

```text
一筆日誌資料的 Java 表示方式。
```

---

### 6.3 `LogParser.java`｜日誌解析器

`LogParser.java` 負責把文字 log 解析成 `LogEntry` 物件。

它做的事情是：

1. 讀取 log 檔案所有行數
2. 跳過空白行
3. 跳過 `#` 開頭的註解行
4. 將每一行 log 切成欄位
5. 將欄位轉成 `LogEntry`
6. 如果格式錯誤，丟出錯誤訊息

預期 log 格式：

```text
<timestamp> <level> <sourceIp> <username> <eventType> <message>
```

範例：

```text
2026-07-04T10:00:00Z INFO 203.0.113.10 alice LOGIN_FAILED Invalid password
```

會被拆成：

```text
timestamp = 2026-07-04T10:00:00Z
level     = INFO
sourceIp  = 203.0.113.10
username  = alice
eventType = LOGIN_FAILED
message   = Invalid password
```

可以把 `LogParser.java` 理解成：

```text
把文字 log 翻譯成 Java 物件的解析器。
```

---

### 6.4 `SecurityRule.java`｜資安偵測規則介面

`SecurityRule.java` 是一個 interface。

它定義所有資安偵測規則都必須具備的功能。

每一條規則都要實作：

```java
String name();
List<DetectionResult> analyze(List<LogEntry> entries);
```

意思是：

| 方法 | 功能 |
|---|---|
| `name()` | 回傳規則名稱 |
| `analyze()` | 分析 log 並回傳偵測結果 |

目前有三個 class 實作它：

- `BruteForceRule.java`
- `InjectionPatternRule.java`
- `SuspiciousToolRule.java`

這樣設計的好處是：

```text
未來要新增規則時，不需要大改主程式，只要新增一個 class 實作 SecurityRule。
```

例如未來可以新增：

- `BlocklistIpRule.java`
- `SensitivePathAccessRule.java`
- `TooMany404Rule.java`
- `ImpossibleTravelLoginRule.java`

可以把 `SecurityRule.java` 理解成：

```text
所有資安偵測規則共同遵守的規格。
```

---

### 6.5 `RuleEngine.java`｜規則引擎

`RuleEngine.java` 負責執行所有資安偵測規則。

它會接收：

```text
List<SecurityRule>
```

也就是多條偵測規則。

然後對同一批 log 依序執行：

```text
BruteForceRule
InjectionPatternRule
SuspiciousToolRule
```

最後把所有結果合併成：

```text
List<DetectionResult>
```

它還會依照：

1. 風險等級
2. 規則名稱
3. 摘要內容

進行排序。

可以把 `RuleEngine.java` 理解成：

```text
負責統一執行所有資安規則的引擎。
```

---

### 6.6 `BruteForceRule.java`｜暴力破解登入偵測規則

`BruteForceRule.java` 用來偵測暴力破解登入。

它的邏輯是：

1. 從所有 log 裡找出 `eventType = LOGIN_FAILED`
2. 依照 `sourceIp` 分組
3. 將同一 IP 的登入失敗事件依時間排序
4. 檢查指定時間區間內是否超過失敗次數門檻
5. 如果超過門檻，就產生 HIGH 風險告警

預設條件：

```text
10 分鐘內，同一 IP 登入失敗 5 次以上。
```

範例告警：

```text
IP 203.0.113.10 generated 5 failed logins within 10 minutes.
```

它會把最多 5 筆相關 log 放進 evidence，方便追查。

可以把 `BruteForceRule.java` 理解成：

```text
偵測有人是否在短時間內一直猜密碼。
```

---

### 6.7 `InjectionPatternRule.java`｜Web Injection 可疑字串偵測規則

`InjectionPatternRule.java` 用來偵測常見 Web 攻擊 payload。

它使用 Regular Expression，也就是正規表示式，檢查 `message` 裡面是否有可疑字串。

目前偵測內容包含：

| 類型 | 可疑字串範例 |
|---|---|
| SQL Injection | `UNION SELECT` |
| SQL Injection | `' OR '1'='1` |
| SQL Injection | `DROP TABLE` |
| SQL Injection | `SELECT ... FROM` |
| XSS | `<script>` |
| Path Traversal | `../` |
| Sensitive File Access | `/etc/passwd` |

如果找到可疑字串，就會產生 HIGH 風險告警。

範例告警：

```text
Suspicious web payload from 198.51.100.23 user=guest
```

可以把 `InjectionPatternRule.java` 理解成：

```text
偵測 log 裡是否出現常見 Web 攻擊字串。
```

---

### 6.8 `SuspiciousToolRule.java`｜掃描工具特徵偵測規則

`SuspiciousToolRule.java` 用來偵測可疑掃描工具或弱點測試工具的特徵。

它會把 log 的 `message` 轉成小寫，然後檢查裡面是否包含以下關鍵字：

```text
sqlmap
nikto
nmap
masscan
gobuster
dirbuster
wpscan
```

如果找到，就產生 MEDIUM 風險告警。

範例：

```text
GET /wp-login.php sqlmap/1.7
```

可能代表有人使用 sqlmap 測試 SQL Injection。

範例告警：

```text
Possible scanner/tool signature detected: sqlmap from 192.0.2.80
```

可以把 `SuspiciousToolRule.java` 理解成：

```text
偵測有沒有人使用常見資安掃描工具來掃你的服務。
```

---

### 6.9 `DetectionResult.java`｜偵測結果模型

`DetectionResult.java` 代表一筆偵測結果。

每當某一條規則發現可疑事件，就會產生一個 `DetectionResult`。

欄位如下：

| 欄位 | 說明 |
|---|---|
| `ruleName` | 是哪一條規則偵測到的 |
| `severity` | 風險等級 |
| `summary` | 告警摘要 |
| `evidence` | 證據 log |

範例：

```text
ruleName = Brute Force Login Detection
severity = HIGH
summary  = IP 203.0.113.10 generated 5 failed logins within 10 minutes.
evidence = 相關 log 紀錄
```

可以把 `DetectionResult.java` 理解成：

```text
一筆資安告警結果。
```

---

### 6.10 `ReportFormatter.java`｜報告產生器

`ReportFormatter.java` 負責把偵測結果轉成報告。

目前支援兩種格式：

1. Markdown
2. JSON

Markdown 適合人閱讀，例如 GitHub、文件、報告。

JSON 適合系統使用，例如未來串接 Web Dashboard 或 API。

Markdown 範例：

```markdown
# Security Log Analysis Report

Total findings: 4

## 1. Brute Force Login Detection

- Severity: **HIGH**
- Summary: IP 203.0.113.10 generated 5 failed logins within 10 minutes.
```

JSON 範例：

```json
{
  "totalFindings": 4,
  "findings": [
    {
      "ruleName": "Brute Force Login Detection",
      "severity": "HIGH",
      "summary": "IP 203.0.113.10 generated 5 failed logins within 10 minutes.",
      "evidence": []
    }
  ]
}
```

可以把 `ReportFormatter.java` 理解成：

```text
把資安告警整理成報告的工具。
```

---

### 6.11 `Severity.java`｜風險等級

`Severity.java` 是 enum，用來定義告警嚴重程度。

目前有三種：

```text
LOW
MEDIUM
HIGH
```

目前專案使用方式：

| 偵測規則 | 風險等級 |
|---|---|
| 暴力破解登入 | HIGH |
| Web Injection | HIGH |
| 掃描工具特徵 | MEDIUM |

可以把 `Severity.java` 理解成：

```text
定義告警風險等級的清單。
```

---

## 7. 測試程式功能說明

測試程式放在：

```text
src/test/java/com/renkai/securitylog/
```

---

### 7.1 `LogParserTest.java`

這是 `LogParser` 的單元測試。

它負責確認：

1. 正確格式的 log 可以被成功解析
2. 解析後的欄位內容是否正確
3. 錯誤格式的 log 會被拒絕

測試重點：

```text
確保 LogParser 不會把 log 欄位解析錯。
```

例如確認：

```text
sourceIp = 203.0.113.10
username = alice
eventType = LOGIN_FAILED
message = Invalid password
```

---

### 7.2 `RuleEngineTest.java`

這是 `RuleEngine` 與偵測規則的整合測試。

它負責確認：

1. 多筆登入失敗可以觸發 Brute Force 告警
2. SQL Injection payload 可以觸發 Injection 告警
3. RuleEngine 可以正確回傳多個 DetectionResult

測試重點：

```text
確保偵測規則真的有被執行，而且可以產生正確結果。
```

---

## 8. Log 格式說明

本專案預設每一行 log 格式如下：

```text
<timestamp> <level> <sourceIp> <username> <eventType> <message>
```

欄位說明：

| 欄位 | 說明 | 範例 |
|---|---|---|
| `timestamp` | 事件發生時間，使用 ISO-8601 格式 | `2026-07-04T10:00:00Z` |
| `level` | 日誌等級 | `INFO`, `WARN`, `ERROR` |
| `sourceIp` | 來源 IP | `203.0.113.10` |
| `username` | 使用者名稱 | `alice`, `guest` |
| `eventType` | 事件類型 | `LOGIN_FAILED`, `LOGIN_SUCCESS`, `HTTP_REQUEST` |
| `message` | 詳細訊息 | `Invalid password` |

範例：

```text
2026-07-04T10:00:00Z INFO 203.0.113.10 alice LOGIN_FAILED Invalid password
2026-07-04T10:08:00Z WARN 198.51.100.23 guest HTTP_REQUEST GET /products?id=1' OR '1'='1 Mozilla/5.0
```

---

## 9. 安裝需求

需要先安裝：

- Java 8 JDK
- Maven 3.x
- Git，若要上傳 GitHub 才需要

確認 Java：

```bash
java -version
```

應該看到類似：

```text
java version "1.8.0_xxx"
```

確認 Java 編譯器：

```bash
javac -version
```

應該看到類似：

```text
javac 1.8.0_xxx
```

確認 Maven：

```bash
mvn -version
```

---

## 10. 如何執行

### 10.1 執行測試

```bash
mvn test
```

用途：

```text
執行 JUnit 測試，確認程式功能正常。
```

---

### 10.2 打包成 jar

```bash
mvn package
```

用途：

```text
將專案編譯並打包成可執行 jar。
```

打包成功後會產生：

```text
target/security-log-analyzer-1.0.0.jar
```

---

### 10.3 分析範例日誌

```bash
java -jar target/security-log-analyzer-1.0.0.jar samples/security-events.log
```

用途：

```text
讀取 samples/security-events.log，並輸出 Markdown 報告。
```

---

### 10.4 輸出 JSON 報告

```bash
java -jar target/security-log-analyzer-1.0.0.jar samples/security-events.log --format json
```

用途：

```text
將分析結果輸出為 JSON 格式。
```

---

### 10.5 將報告輸出成檔案

```bash
java -jar target/security-log-analyzer-1.0.0.jar samples/security-events.log --output report.md
```

用途：

```text
將 Markdown 報告寫入 report.md 檔案。
```

---

### 10.6 調整暴力破解偵測條件

```bash
java -jar target/security-log-analyzer-1.0.0.jar samples/security-events.log --failed-threshold 3 --window-minutes 5
```

意思是：

```text
5 分鐘內，同一個 IP 登入失敗 3 次以上，就產生告警。
```

---

## 11. 執行結果範例

Markdown 輸出範例：

```markdown
# Security Log Analysis Report

Total findings: 4

## 1. Brute Force Login Detection

- Severity: **HIGH**
- Summary: IP 203.0.113.10 generated 5 failed logins within 10 minutes.
- Evidence:
  - `2026-07-04T10:00:00Z 203.0.113.10 alice LOGIN_FAILED Invalid password`
  - `2026-07-04T10:01:00Z 203.0.113.10 alice LOGIN_FAILED Invalid password`
```

JSON 輸出範例：

```json
{
  "totalFindings": 4,
  "findings": [
    {
      "ruleName": "Brute Force Login Detection",
      "severity": "HIGH",
      "summary": "IP 203.0.113.10 generated 5 failed logins within 10 minutes.",
      "evidence": [
        "2026-07-04T10:00:00Z 203.0.113.10 alice LOGIN_FAILED Invalid password"
      ]
    }
  ]
}
```

---

## 12. 專案注意事項

此專案只用於：

- 防禦型資安學習
- 日誌分析練習
- SOC Log Analysis Demo

此專案不包含：

- 自動化攻擊
- 未授權掃描
- 入侵功能
- 密碼破解功能
- 惡意程式功能

---

## 13. 專案英文簡介

A defensive Java 8 cybersecurity portfolio project that analyzes security logs and detects suspicious activities such as brute force login attempts, web injection payloads, and suspicious scanner tool signatures. The project demonstrates Java CLI development, rule-based detection design, Maven build management, JUnit testing, and GitHub Actions CI.
