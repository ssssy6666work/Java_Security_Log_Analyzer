# Java Security Log Analyzer｜Java 資安日誌異常偵測器

這是一個使用 **Java** 開發的防禦型資安作品集專案，用來分析安全事件日誌，並偵測常見的可疑行為，例如：

- 暴力破解登入 Brute Force Login
- SQL Injection 可疑字串
- XSS 可疑字串
- Path Traversal 可疑路徑存取
- sqlmap、nmap、nikto、Nessus、OpenVAS、ZAP 等掃描工具特徵

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

- 使用 Java，符合當初學習基礎 Java 的版本
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
- acunetix
- nessus
- openvas
- zap

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
│   ├── brute-force-test.log
│   ├── injection-test.log
│   ├── invalid-test.log
│   ├── normal-test.log
│   ├── not-brute-force.log
│   ├── security-events.log
│   └── tool-test.log
├── src/
│   ├── main/
│   │   └── java/
│   │       └── com/
│   │           └── renkai/
│   │               └── securitylog/
│   │                   ├── BruteForceRule.java
│   │                   ├── DetectionResult.java
│   │                   ├── InjectionPatternRule.java
│   │                   ├── LogEntry.java
│   │                   ├── LogParser.java
│   │                   ├── Main.java
│   │                   ├── ReportFormatter.java
│   │                   ├── RuleEngine.java
│   │                   ├── SecurityRule.java
│   │                   ├── Severity.java
│   │                   └── SuspiciousToolRule.java
│   └── test/
│       └── java/
│           └── com/
│               └── renkai/
│                   └── securitylog/
│                       ├── LogParserTest.java
│                       └── RuleEngineTest.java
├── target/
│   ├── classes/
│   │   └── com/
│   │       └── renkai/
│   │           └── securitylog/
│   │               ├── BruteForceRule.class
│   │               ├── DetectionResult.class
│   │               ├── InjectionPatternRule.class
│   │               ├── LogEntry.class
│   │               ├── LogParser.class
│   │               ├── Main$CliConfig.class
│   │               ├── Main.class
│   │               ├── ReportFormatter.class
│   │               ├── RuleEngine.class
│   │               ├── SecurityRule.class
│   │               ├── Severity.class
│   │               └── SuspiciousToolRule.class
│   ├── generated-sources/
│   │   └── annotations/
│   ├── generated-test-sources/
│   │   └── test-annotations/
│   ├── maven-archiver/
│   │   └── pom.properties
│   ├── maven-status/
│   │   └── maven-compiler-plugin/
│   │       ├── compile/
│   │       │   └── default-compile/
│   │       │       ├── createdFiles.lst
│   │       │       └── inputFiles.lst
│   │       └── testCompile/
│   │           └── default-testCompile/
│   │               ├── createdFiles.lst
│   │               └── inputFiles.lst
│   ├── surefire-reports/
│   │   ├── com.renkai.securitylog.LogParserTest.txt
│   │   ├── com.renkai.securitylog.RuleEngineTest.txt
│   │   ├── TEST-com.renkai.securitylog.LogParserTest.xml
│   │   └── TEST-com.renkai.securitylog.RuleEngineTest.xml
│   ├── test-classes/
│   │   └── com/
│   │       └── renkai/
│   │           └── securitylog/
│   │               ├── LogParserTest.class
│   │               └── RuleEngineTest.class
│   └── security-log-analyzer-1.0.0.jar
├── report.md
├── report.json
├── pom.xml
├── .gitignore
├── LICENSE
└── README.md
```

`report.md` 與 `report.json` 是使用 `samples/security-events.log` 產生的主要分析結果，兩者都記錄：

```text
Total findings: 5
```

`target/` 是 Maven 執行編譯、測試與打包後產生的完整輸出資料夾，包含：

- 主程式編譯後的 `.class`
- 測試程式編譯後的 `.class`
- 可執行的 JAR
- Maven 編譯狀態資料
- JUnit Surefire 測試報告
- 產生原始碼與測試原始碼的預留資料夾

各項測試的預期結果直接記錄在 README，主要完整報告則保留在專案根目錄的 `report.md` 與 `report.json`。

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

### 5.2 `samples/`｜測試日誌資料

`samples/` 裡放入專案實際使用的 7 個測試 log。

| 檔案 | 用途 | 預期結果 |
|---|---|---|
| `security-events.log` | 綜合測試：暴力破解、SQL Injection、XSS、sqlmap、Nessus | `Total findings: 5` |
| `brute-force-test.log` | 5 筆登入失敗，測試暴力破解與時間範圍 | 預設 1 筆；3 分鐘視窗 0 筆；5 分鐘視窗 1 筆 |
| `not-brute-force.log` | 只有 4 筆登入失敗，未達預設門檻 | `Total findings: 0` |
| `injection-test.log` | 包含 `OR '1'='1` 的 SQL Injection 特徵 | `Total findings: 1` |
| `tool-test.log` | 包含 sqlmap 與 Nessus | `Total findings: 2` |
| `normal-test.log` | 正常登入與一般網頁請求 | `Total findings: 0` |
| `invalid-test.log` | 故意放入錯誤格式 | 拋出 `IllegalArgumentException` |

其中 XSS 測試資料已包含在 `security-events.log`：

```text
2026-07-04T10:09:00Z WARN 198.51.100.24 guest HTTP_REQUEST GET /search?q=<script>alert(1)</script> Mozilla/5.0
```

### 5.3 `target/`｜完整編譯、測試與打包結果

`target/` 是執行 Maven 後產生的完整輸出資料夾。

主要內容：

| 路徑 | 功能 |
|---|---|
| `target/classes/` | 主程式 Java 原始碼編譯後的 `.class` |
| `target/test-classes/` | JUnit 測試程式編譯後的 `.class` |
| `target/security-log-analyzer-1.0.0.jar` | 可直接執行的 JAR |
| `target/surefire-reports/` | Maven Surefire 產生的 JUnit 測試報告 |
| `target/maven-status/` | Maven Compiler Plugin 的編譯紀錄 |
| `target/maven-archiver/pom.properties` | JAR 專案資訊 |
| `target/generated-sources/annotations/` | Maven 產生原始碼的預留位置 |
| `target/generated-test-sources/test-annotations/` | Maven 產生測試原始碼的預留位置 |

Surefire 文字報告顯示：

```text
LogParserTest：Tests run: 2, Failures: 0, Errors: 0, Skipped: 0
RuleEngineTest：Tests run: 1, Failures: 0, Errors: 0, Skipped: 0
```

合計：

```text
Tests run: 3, Failures: 0, Errors: 0, Skipped: 0
```

### 5.4 `report.md` 與 `report.json`｜主要執行結果

這兩個檔案是使用綜合範例 `samples/security-events.log` 產生的主要報告。

結果為：

```text
Total findings: 5
```

5 筆告警包含：

1. 暴力破解登入 1 筆
2. Web Injection 2 筆：SQL Injection、XSS
3. 掃描工具特徵 2 筆：Nessus、sqlmap

---

## 6. Java 程式檔案功能說明

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
acunetix
nessus
openvas
zap
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

Total findings: 5

## 1. Brute Force Login Detection

- Severity: **HIGH**
- Summary: IP 203.0.113.10 generated 5 failed logins within 10 minutes.
```

JSON 範例：

```json
{
  "totalFindings": 5,
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

目前共有兩個測試檔案、三個測試案例：

| 測試檔案 | 測試方法 | 測試目的 |
|---|---|---|
| `LogParserTest.java` | `parseValidLine()` | 正確格式的 log 能否被正確解析 |
| `LogParserTest.java` | `rejectInvalidLine()` | 錯誤格式的 log 能否被正確拒絕 |
| `RuleEngineTest.java` | `detectBruteForceAndInjection()` | 規則引擎能否抓到暴力破解與 Injection |

---

### 7.1 `LogParserTest.java`：測試一 `parseValidLine()`

這個測試會把一行正確格式的 log 交給 `LogParser`：

```text
2026-07-04T10:00:00Z INFO 203.0.113.10 alice LOGIN_FAILED Invalid password
```

接著確認解析後的每個欄位都正確：

```text
timestamp = 2026-07-04T10:00:00Z
level     = INFO
sourceIp  = 203.0.113.10
username  = alice
eventType = LOGIN_FAILED
message   = Invalid password
```

測試概念：

```text
輸入正確格式的 log
    ↓
LogParser 進行解析
    ↓
確認每個欄位都與預期相同
```

如果任何欄位解析錯誤，例如 IP、事件類型或訊息內容不一致，測試就會失敗。

---

### 7.2 `LogParserTest.java`：測試二 `rejectInvalidLine()`

這個測試故意傳入錯誤格式：

```text
invalid line
```

正常 log 至少需要包含：

```text
timestamp level sourceIp username eventType message
```

因此 `invalid line` 不符合格式，`LogParser` 應該拋出：

```java
IllegalArgumentException
```

測試使用：

```java
assertThrows(IllegalArgumentException.class, ...)
```

意思是：

```text
預期程式遇到錯誤格式時，必須拒絕資料並拋出指定例外。
```

判斷方式：

| 實際情況 | 測試結果 |
|---|---|
| 正確拋出 `IllegalArgumentException` | 通過 |
| 完全沒有拋出例外 | 失敗 |
| 拋出其他種類的例外 | 失敗 |

這不是在測試程式會不會故障，而是在確認程式不會把錯誤資料當成正常日誌。

---

### 7.3 `RuleEngineTest.java`：測試三 `detectBruteForceAndInjection()`

這個測試準備四筆日誌。

前三筆是同一個 IP 在短時間內連續登入失敗：

```text
10:00　203.0.113.10　LOGIN_FAILED
10:01　203.0.113.10　LOGIN_FAILED
10:02　203.0.113.10　LOGIN_FAILED
```

暴力破解規則設定為：

```java
new BruteForceRule(3, Duration.ofMinutes(5))
```

意思是：

```text
同一個 IP 在 5 分鐘內登入失敗 3 次，就產生暴力破解告警。
```

第四筆日誌包含：

```text
OR '1'='1
```

這是 `InjectionPatternRule` 會偵測的 SQL Injection 可疑特徵。

因此預期結果為：

```text
暴力破解告警：1 筆
Injection 告警：1 筆
總結果：2 筆
```

測試最後會確認：

1. `results.size()` 必須等於 2。
2. 結果中至少有一筆規則名稱包含 `Brute Force`。
3. 結果中至少有一筆規則名稱包含 `Injection`。

測試概念：

```text
準備可疑日誌
    ↓
建立 BruteForceRule 與 InjectionPatternRule
    ↓
RuleEngine 執行所有規則
    ↓
應該得到 2 筆 DetectionResult
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

注意：

- 空白行會被略過。
- `#` 開頭的行會被視為註解並略過。
- 時間格式必須能被 `Instant.parse()` 解析，例如 `2026-07-04T10:00:00Z`。
- 欄位不足時會拋出 `IllegalArgumentException`。

---

## 9. 安裝需求

需要先安裝：

- Java 8 JDK
- Maven 3.x
- Git，若要上傳 GitHub 才需要

### 9.1 解壓縮專案

請先將 ZIP 完整解壓縮，不要直接在壓縮檔裡執行。

進入專案資料夾後，應該看到：

```text
pom.xml
README.md
samples
src
```

`pom.xml` 是 Maven 專案的重要設定檔。後續指令都必須在包含 `pom.xml` 的資料夾執行。

### 9.2 在 Windows 開啟 CMD

1. 使用檔案總管進入專案資料夾。
2. 點選上方網址列。
3. 輸入 `cmd`。
4. 按 Enter。

先輸入：

```bat
dir
```

確認清單中有 `pom.xml`。

### 9.3 確認 Java

```bash
java -version
```

應該看到類似：

```text
java version "1.8.0_xxx"
```

再確認 Java 編譯器：

```bash
javac -version
```

應該看到類似：

```text
javac 1.8.0_xxx
```

如果 `java` 可以執行，但 `javac` 不行，可能只有安裝 JRE，沒有安裝完整 JDK。

### 9.4 確認 Maven

```bash
mvn -version
```

應該看到類似：

```text
Apache Maven 3.x.x
Java version: 1.8.0_xxx
```

---

## 10. 完整單元測試方法

### 10.1 執行全部三個測試

```bash
mvn clean test
```

指令說明：

- `clean`：刪除上一次產生的編譯與測試檔案。
- `test`：重新編譯並執行所有 JUnit 測試。

成功時應該看到：

```text
Tests run: 3, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

判讀方式：

| 顯示內容 | 意思 |
|---|---|
| `Tests run: 3` | 總共執行 3 個測試 |
| `Failures: 0` | 預期結果不一致的測試為 0 |
| `Errors: 0` | 執行中發生錯誤的測試為 0 |
| `Skipped: 0` | 沒有任何測試被略過 |
| `BUILD SUCCESS` | 測試與建置成功 |

---

### 10.2 只執行 `LogParserTest`

```bash
mvn -Dtest=LogParserTest test
```

預期：

```text
Tests run: 2, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

這會執行：

- `parseValidLine()`
- `rejectInvalidLine()`

---

### 10.3 只執行測試一

```bash
mvn "-Dtest=LogParserTest#parseValidLine" test
```

預期：

```text
Tests run: 1, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

---

### 10.4 只執行測試二

```bash
mvn "-Dtest=LogParserTest#rejectInvalidLine" test
```

預期：

```text
Tests run: 1, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

測試二成功代表：

```text
錯誤格式的 log 有被正確拒絕。
```

---

### 10.5 只執行 `RuleEngineTest`

```bash
mvn -Dtest=RuleEngineTest test
```

預期：

```text
Tests run: 1, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

---

### 10.6 只執行測試三

```bash
mvn "-Dtest=RuleEngineTest#detectBruteForceAndInjection" test
```

預期：

```text
Tests run: 1, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

測試三成功代表：

```text
規則引擎成功找到 1 筆暴力破解告警與 1 筆 Injection 告警。
```

---

### 10.7 查看 Maven 測試報告

執行測試後，報告會產生在：

```text
target/surefire-reports/
```

通常會看到：

```text
com.renkai.securitylog.LogParserTest.txt
com.renkai.securitylog.RuleEngineTest.txt
TEST-com.renkai.securitylog.LogParserTest.xml
TEST-com.renkai.securitylog.RuleEngineTest.xml
```

Windows 可輸入：

```bat
dir target\surefire-reports
```

`.txt` 適合直接閱讀，`.xml` 適合 CI/CD 或其他工具處理。

---

## 11. 打包與實際功能測試

### 11.1 打包成可執行 JAR

```bash
mvn clean package
```

這個指令會：

```text
刪除舊檔案
    ↓
編譯主程式
    ↓
編譯測試程式
    ↓
執行全部測試
    ↓
產生 JAR
```

成功時應該看到：

```text
Tests run: 3, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

JAR 位置：

```text
target/security-log-analyzer-1.0.0.jar
```

---

### 11.2 分析專案內建範例日誌

```bash
java -jar target/security-log-analyzer-1.0.0.jar samples/security-events.log
```

目前範例日誌應該產生：

```text
Total findings: 5
```

五筆告警為：

| 告警類型 | 數量 | 原因 |
|---|---:|---|
| Brute Force Login Detection | 1 | 同一 IP 在 10 分鐘內登入失敗 5 次 |
| Web Injection Pattern Detection | 2 | 一筆 SQL Injection、一筆 XSS |
| Suspicious Security Tool Signature Detection | 2 | 一筆 `sqlmap`、一筆 `nessus` |
| 合計 | 5 | 共 5 筆偵測結果 |

### 11.2.1 最後一次實際測試結果：共 5 筆告警

最後一次使用專案內建範例日誌進行測試，執行指令如下：

```bash
java -jar target/security-log-analyzer-1.0.0.jar samples/security-events.log
```

實際輸出開頭為：

```text
# Security Log Analysis Report

Total findings: 5
```

這次測試實際找到的 5 筆告警如下：

```text
1. Brute Force Login Detection
   IP 203.0.113.10 在 10 分鐘內登入失敗 5 次。

2. Web Injection Pattern Detection
   IP 198.51.100.23 的請求包含 SQL Injection 特徵：OR '1'='1。

3. Web Injection Pattern Detection
   IP 198.51.100.24 的請求包含 XSS 特徵：<script>alert(1)</script>。

4. Suspicious Security Tool Signature Detection
   IP 198.51.100.88 的日誌包含 Nessus 掃描工具特徵。

5. Suspicious Security Tool Signature Detection
   IP 192.0.2.80 的日誌包含 sqlmap 掃描工具特徵。
```

測試結果統計：

| 偵測規則 | 數量 |
|---|---:|
| Brute Force Login Detection | 1 |
| Web Injection Pattern Detection | 2 |
| Suspicious Security Tool Signature Detection | 2 |
| **Total findings** | **5** |

這代表範例日誌中的暴力破解、SQL Injection、XSS、Nessus 與 sqlmap 特徵都已被程式成功偵測。

如果看到舊的 `report.md` 顯示 `Total findings: 4`，可能只是舊報告尚未重新產生。直接執行程式只會顯示在畫面上，不會自動更新既有的 `report.md`。

---

### 11.3 輸出 Markdown 報告

```bash
java -jar target/security-log-analyzer-1.0.0.jar samples/security-events.log --output report.md
```

成功時會顯示：

```text
Report written to: report.md
```

重新打開 `report.md` 後，應該看到：

```text
Total findings: 5
```

---

### 11.4 直接顯示 JSON 報告

```bash
java -jar target/security-log-analyzer-1.0.0.jar samples/security-events.log --format json
```

應該包含：

```json
{
  "totalFindings": 5,
  "findings": []
}
```

實際的 `findings` 陣列中會包含五筆完整結果。

---

### 11.5 輸出 JSON 檔案

```bash
java -jar target/security-log-analyzer-1.0.0.jar samples/security-events.log --format json --output report.json
```

成功後會產生：

```text
report.json
```

---

### 11.6 調整暴力破解偵測條件

```bash
java -jar target/security-log-analyzer-1.0.0.jar samples/security-events.log --failed-threshold 3 --window-minutes 5
```

意思是：

```text
5 分鐘內，同一個 IP 登入失敗 3 次以上，就產生告警。
```

參數說明：

| 參數 | 功能 | 預設值 |
|---|---|---:|
| `--failed-threshold` | 登入失敗次數門檻 | 5 |
| `--window-minutes` | 判斷時間範圍 | 10 |
| `--format` | `markdown` 或 `json` | markdown |
| `--output` | 將報告寫入指定檔案 | 不輸出檔案 |

---

## 12. 使用 samples 測試日誌

`samples/` 已經放入所有實際測試會使用的 log，可以直接執行，不需要另外建立資料夾。

### 12.1 測試正常日誌

使用：

```text
samples/normal-test.log
```

執行：

```bash
java -jar target/security-log-analyzer-1.0.0.jar samples/normal-test.log
```

預期：

```text
Total findings: 0
No suspicious activity detected.
```

這個測試是確認程式不會把普通日誌誤判成攻擊。

---

### 12.2 測試暴力破解

使用：

```text
samples/brute-force-test.log
```

這個檔案包含同一個 IP 在 5 分鐘內登入失敗 5 次。

執行：

```bash
java -jar target/security-log-analyzer-1.0.0.jar samples/brute-force-test.log
```

預期：

```text
Total findings: 1
Brute Force Login Detection
```

---

### 12.3 測試未達暴力破解門檻

使用只有 4 筆登入失敗的測試檔：

```text
samples/not-brute-force.log
```

執行：

```bash
java -jar target/security-log-analyzer-1.0.0.jar samples/not-brute-force.log
```

預設門檻是 5 次，因此預期：

```text
Total findings: 0
No suspicious activity detected.
```

也可以把門檻改成 3：

```bash
java -jar target/security-log-analyzer-1.0.0.jar samples/not-brute-force.log --failed-threshold 3
```

這時預期會觸發 1 筆暴力破解告警。

---

### 12.4 測試 SQL Injection

使用：

```text
samples/injection-test.log
```

執行：

```bash
java -jar target/security-log-analyzer-1.0.0.jar samples/injection-test.log
```

預期：

```text
Total findings: 1
Web Injection Pattern Detection
```

---

### 12.5 測試 XSS

XSS 測試資料放在綜合範例：

```text
samples/security-events.log
```

其中包含：

```text
2026-07-04T10:09:00Z WARN 198.51.100.24 guest HTTP_REQUEST GET /search?q=<script>alert(1)</script> Mozilla/5.0
```

執行：

```bash
java -jar target/security-log-analyzer-1.0.0.jar samples/security-events.log
```

完整綜合測試預期：

```text
Total findings: 5
```

其中有一筆 `Web Injection Pattern Detection` 是由 `<script>` XSS 特徵觸發。

---

### 12.6 測試掃描工具特徵

使用：

```text
samples/tool-test.log
```

執行：

```bash
java -jar target/security-log-analyzer-1.0.0.jar samples/tool-test.log
```

預期：

```text
Total findings: 2
```

兩筆結果分別偵測 `sqlmap` 與 `nessus`。

---

### 12.7 測試錯誤格式

使用：

```text
samples/invalid-test.log
```

執行：

```bash
java -jar target/security-log-analyzer-1.0.0.jar samples/invalid-test.log
```

預期看到類似：

```text
IllegalArgumentException
Invalid log format at line 1
```

這代表錯誤格式有被正確拒絕，與 `rejectInvalidLine()` 單元測試的目的相同。

---

## 13. GitHub Actions 自動測試

專案內的：

```text
.github/workflows/maven-test.yml
```

會在程式推送到 GitHub 時自動執行 Maven 測試。

流程可以理解成：

```text
程式上傳到 GitHub
    ↓
GitHub Actions 建立 Java 8 環境
    ↓
執行 mvn test
    ↓
測試成功顯示綠色勾勾
測試失敗顯示紅色叉叉
```

這能展現基本的 CI/CD 與自動化測試概念。

---

## 14. 常見錯誤排除

### 14.1 找不到 `mvn`

錯誤：

```text
'mvn' 不是內部或外部命令
```

原因：

- Maven 尚未安裝。
- Maven 的 `bin` 路徑尚未加入 Windows `PATH`。

完成設定後，關閉 CMD 並重新開啟，再執行：

```bash
mvn -version
```

---

### 14.2 找不到 `pom.xml`

錯誤可能包含：

```text
there is no POM in this directory
```

請執行：

```bat
dir
```

確認目前資料夾中有 `pom.xml`。

---

### 14.3 找不到 JAR

錯誤：

```text
Unable to access jarfile target/security-log-analyzer-1.0.0.jar
```

先執行：

```bash
mvn clean package
```

看到 `BUILD SUCCESS` 後，再執行 JAR。

---

### 14.4 報告仍顯示 4 筆

直接執行：

```bash
java -jar target/security-log-analyzer-1.0.0.jar samples/security-events.log
```

只會將新結果顯示在終端機，不會自動更新舊 `report.md`。

請重新輸出：

```bash
java -jar target/security-log-analyzer-1.0.0.jar samples/security-events.log --output report.md
```

目前範例日誌正確結果應為：

```text
Total findings: 5
```

---

## 15. 執行結果範例

Markdown 輸出範例：

```markdown
# Security Log Analysis Report

Total findings: 5

## 1. Brute Force Login Detection

- Severity: **HIGH**
- Summary: IP 203.0.113.10 generated 5 failed logins within 10 minutes.
- Evidence:
  - `2026-07-04T10:00:00Z 203.0.113.10 alice LOGIN_FAILED Invalid password`

## 2. Web Injection Pattern Detection

- Severity: **HIGH**
- Summary: Suspicious web payload from 198.51.100.23 user=guest

## 3. Web Injection Pattern Detection

- Severity: **HIGH**
- Summary: Suspicious web payload from 198.51.100.24 user=guest

## 4. Suspicious Security Tool Signature Detection

- Severity: **MEDIUM**
- Summary: Possible scanner/tool signature detected: nessus from 198.51.100.88

## 5. Suspicious Security Tool Signature Detection

- Severity: **MEDIUM**
- Summary: Possible scanner/tool signature detected: sqlmap from 192.0.2.80
```

JSON 輸出範例：

```json
{
  "totalFindings": 5,
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

## 16. 完整測試成功標準

專案完整測試成功時，應該符合：

| 測試項目 | 預期結果 |
|---|---|
| 全部 JUnit 測試 | 3 個全部通過 |
| 測試一 | 正確 log 的六個欄位解析正確 |
| 測試二 | 錯誤格式被正確拒絕 |
| 測試三 | 找到 1 筆暴力破解與 1 筆 Injection |
| Maven 打包 | 顯示 `BUILD SUCCESS` |
| 範例日誌 | `Total findings: 5` |
| 正常日誌 | `Total findings: 0` |
| Markdown 輸出 | 成功產生 `.md` |
| JSON 輸出 | 成功產生或顯示 JSON |

最重要的成功畫面：

```text
Tests run: 3, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

範例日誌分析成功畫面：

```text
Total findings: 5
```

---

## 17. 專案注意事項

此專案只用於：

- 防禦型資安學習
- 日誌分析練習
- SOC Log Analysis Demo
- Java、Maven、JUnit 與 GitHub Actions 練習

此專案不包含：

- 自動化攻擊
- 未授權掃描
- 入侵功能
- 密碼破解功能
- 惡意程式功能

---

## 18. 自訂暴力破解時間範圍測試

這個測試用來確認 `--window-minutes` 參數是否會影響暴力破解判斷。

專案已提供：

```text
samples/brute-force-test.log
```

內容共有 5 筆登入失敗，時間從 `10:00` 到 `10:04`。

使用 3 分鐘時間範圍：

```bat
java -jar target\security-log-analyzer-1.0.0.jar samples\brute-force-test.log --failed-threshold 5 --window-minutes 3
```

預期：

```text
Total findings: 0
No suspicious activity detected.
```

改用 5 分鐘時間範圍：

```bat
java -jar target\security-log-analyzer-1.0.0.jar samples\brute-force-test.log --failed-threshold 5 --window-minutes 5
```

預期：

```text
Total findings: 1
```

並包含：

```text
Brute Force Login Detection
```

---

## 19. SQL Injection 偵測測試

專案已提供：

```text
samples/injection-test.log
```

內容：

```text
2026-07-04T10:00:00Z WARN 198.51.100.23 guest HTTP_REQUEST GET /products?id=1' OR '1'='1
```

執行：

```bat
java -jar target\security-log-analyzer-1.0.0.jar samples\injection-test.log
```

預期：

```text
Total findings: 1
```

並包含：

```text
Web Injection Pattern Detection
```

---

## 20. XSS 偵測測試

XSS 測試資料包含在綜合測試檔：

```text
samples/security-events.log
```

其中這一筆具有 `<script>` 特徵：

```text
2026-07-04T10:09:00Z WARN 198.51.100.24 guest HTTP_REQUEST GET /search?q=<script>alert(1)</script> Mozilla/5.0
```

執行：

```bat
java -jar target\security-log-analyzer-1.0.0.jar samples\security-events.log
```

完整綜合測試的預期結果是：

```text
Total findings: 5
```

其中會有一筆：

```text
Web Injection Pattern Detection
Suspicious web payload from 198.51.100.24 user=guest
```

這一筆就是 XSS 偵測結果。

---

## 21. 掃描工具特徵測試

專案已提供：

```text
samples/tool-test.log
```

內容：

```text
2026-07-04T10:00:00Z WARN 192.0.2.80 guest HTTP_REQUEST GET /wp-login.php sqlmap/1.7
2026-07-04T10:01:00Z WARN 192.0.2.81 guest HTTP_REQUEST GET /admin Nessus scanner
```

執行：

```bat
java -jar target\security-log-analyzer-1.0.0.jar samples\tool-test.log
```

預期：

```text
Total findings: 2
```

兩筆結果分別偵測到：

```text
sqlmap
nessus
```

---

## 22. 正常日誌測試

專案已提供：

```text
samples/normal-test.log
```

內容只有正常登入與一般網頁請求。

執行：

```bat
java -jar target\security-log-analyzer-1.0.0.jar samples\normal-test.log
```

預期：

```text
Total findings: 0

No suspicious activity detected.
```

這代表正常操作沒有被誤判成攻擊。

---

## 23. 錯誤日誌格式測試

專案已提供：

```text
samples/invalid-test.log
```

內容：

```text
invalid line
```

執行：

```bat
java -jar target\security-log-analyzer-1.0.0.jar samples\invalid-test.log
```

預期看到類似：

```text
IllegalArgumentException
Invalid log format at line 1
```

這不是程式壞掉，而是程式正確拒絕錯誤格式。

---

## 24. 查看 Maven 測試報告

先執行：

```bat
mvn test
```

測試報告會放在：

```text
target/surefire-reports/
```

完整資料夾內有：

```text
com.renkai.securitylog.LogParserTest.txt
com.renkai.securitylog.RuleEngineTest.txt
TEST-com.renkai.securitylog.LogParserTest.xml
TEST-com.renkai.securitylog.RuleEngineTest.xml
```

開啟第一份文字報告：

```bat
notepad target\surefire-reports\com.renkai.securitylog.LogParserTest.txt
```

預期：

```text
Tests run: 2, Failures: 0, Errors: 0, Skipped: 0
```

開啟第二份文字報告：

```bat
notepad target\surefire-reports\com.renkai.securitylog.RuleEngineTest.txt
```

預期：

```text
Tests run: 1, Failures: 0, Errors: 0, Skipped: 0
```

合計：

```text
Tests run: 3, Failures: 0, Errors: 0, Skipped: 0
```

---

## 25. 完整測試指令順序

在包含 `pom.xml` 的專案資料夾開啟 CMD，依序執行：

```bat
java -version
javac -version
mvn -version
dir

mvn clean test
mvn -Dtest=LogParserTest test
mvn "-Dtest=LogParserTest#rejectInvalidLine" test
mvn -Dtest=RuleEngineTest test
mvn "-Dtest=RuleEngineTest#detectBruteForceAndInjection" test

mvn clean package

java -jar target\security-log-analyzer-1.0.0.jar samples\security-events.log
java -jar target\security-log-analyzer-1.0.0.jar samples\security-events.log --format json
java -jar target\security-log-analyzer-1.0.0.jar samples\security-events.log --output report.md
java -jar target\security-log-analyzer-1.0.0.jar samples\security-events.log --format json --output report.json

java -jar target\security-log-analyzer-1.0.0.jar samples\brute-force-test.log
java -jar target\security-log-analyzer-1.0.0.jar samples\brute-force-test.log --failed-threshold 5 --window-minutes 3
java -jar target\security-log-analyzer-1.0.0.jar samples\brute-force-test.log --failed-threshold 5 --window-minutes 5
java -jar target\security-log-analyzer-1.0.0.jar samples\not-brute-force.log
java -jar target\security-log-analyzer-1.0.0.jar samples\injection-test.log
java -jar target\security-log-analyzer-1.0.0.jar samples\tool-test.log
java -jar target\security-log-analyzer-1.0.0.jar samples\normal-test.log
java -jar target\security-log-analyzer-1.0.0.jar samples\invalid-test.log
```

全部單元測試成功時，應該看到：

```text
Tests run: 3, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

最後一次綜合日誌測試：

```bat
java -jar target\security-log-analyzer-1.0.0.jar samples\security-events.log
```

應該看到：

```text
# Security Log Analysis Report

Total findings: 5
```

5 筆告警組成：

| 告警類型 | 數量 |
|---|---:|
| Brute Force Login | 1 |
| Web Injection | 2 |
| Suspicious Security Tool Signature | 2 |
| **總數** | **5** |

完整成功標準：

```text
JUnit 測試：3 個全部通過
Maven 打包：BUILD SUCCESS
範例日誌分析：Total findings: 5
Markdown 報告：成功產生 report.md
JSON 報告：成功產生 report.json
```
---
