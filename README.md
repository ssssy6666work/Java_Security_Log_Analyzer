# Java Security Log Analyzer

一個使用 Java 8 開發的防禦型資安作品集專案，用來分析安全日誌並偵測常見異常行為，例如暴力破解登入、Web Injection Payload、掃描工具特徵等。

這個專案適合放在 GitHub，並可用於履歷、面試作品集、資安轉 RD 或資安工程師職涯展示。

## 專案特色

- 使用 Java 8 與 Maven 建置
- 不依賴大型框架，核心邏輯清楚，方便面試說明
- 支援 CLI 指令執行
- 支援 Markdown 與 JSON 報告輸出
- 內建範例安全日誌
- 內建 JUnit 5 單元測試
- 內建 GitHub Actions CI 測試流程

## 偵測規則

### 1. Brute Force Login Detection

偵測同一個來源 IP 在指定時間內是否出現過多登入失敗紀錄。

預設條件：

- 10 分鐘內
- 同一 IP 登入失敗 5 次以上

### 2. Web Injection Pattern Detection

偵測疑似 SQL Injection、XSS、Path Traversal 等攻擊字串，例如：

- `' OR '1'='1`
- `UNION SELECT`
- `<script>`
- `../`
- `/etc/passwd`

### 3. Suspicious Security Tool Signature Detection

偵測常見掃描工具或弱點測試工具特徵，例如：

- sqlmap
- nikto
- nmap
- masscan
- gobuster
- dirbuster
- wpscan

## 專案結構

```text
java-security-log-analyzer/
├── .github/workflows/maven-test.yml
├── samples/security-events.log
├── src/main/java/com/renkai/securitylog/
│   ├── Main.java
│   ├── LogParser.java
│   ├── LogEntry.java
│   ├── RuleEngine.java
│   ├── SecurityRule.java
│   ├── BruteForceRule.java
│   ├── InjectionPatternRule.java
│   ├── SuspiciousToolRule.java
│   ├── DetectionResult.java
│   ├── ReportFormatter.java
│   └── Severity.java
├── src/test/java/com/renkai/securitylog/
│   ├── LogParserTest.java
│   └── RuleEngineTest.java
├── pom.xml
├── .gitignore
├── LICENSE
└── README.md
```

## 日誌格式

每一行日誌格式如下：

```text
<timestamp> <level> <sourceIp> <username> <eventType> <message>
```

範例：

```text
2026-07-04T10:00:00Z INFO 203.0.113.10 alice LOGIN_FAILED Invalid password
2026-07-04T10:08:00Z WARN 198.51.100.23 guest HTTP_REQUEST GET /products?id=1' OR '1'='1 Mozilla/5.0
```

## 如何執行

需求：Java 8、Maven 3.x。

### 1. 執行測試

```bash
mvn test
```

### 2. 打包專案

```bash
mvn package
```

### 3. 分析範例日誌

```bash
java -jar target/security-log-analyzer-1.0.0.jar samples/security-events.log
```

### 4. 輸出 JSON 報告

```bash
java -jar target/security-log-analyzer-1.0.0.jar samples/security-events.log --format json
```

### 5. 將報告輸出成檔案

```bash
java -jar target/security-log-analyzer-1.0.0.jar samples/security-events.log --output report.md
```

### 6. 調整暴力破解偵測條件

```bash
java -jar target/security-log-analyzer-1.0.0.jar samples/security-events.log --failed-threshold 3 --window-minutes 5
```

## 執行結果範例

```markdown
# Security Log Analysis Report

Total findings: 4

## 1. Brute Force Login Detection

- Severity: **HIGH**
- Summary: IP 203.0.113.10 generated 5 failed logins within 10 minutes.
```

## 可以延伸的功能

這些功能很適合後續 commit 到 GitHub，讓專案看起來有持續維護：

- 加入 CSV / JSON log parser
- 加入 IP allowlist / blocklist
- 加入風險分數 Risk Score
- 加入簡易 Web Dashboard
- 匯出 HTML 報告
- 整合 SQLite 儲存分析結果
- 加入更多 OWASP Top 10 偵測規則
- 加入 Dockerfile

## 履歷可以這樣寫

```text
Java Security Log Analyzer｜個人資安作品集專案
- 使用 Java 8 與 Maven 開發 CLI 日誌分析工具，偵測暴力破解登入、SQL Injection、XSS 與掃描工具特徵。
- 設計 Rule Engine 架構，將不同偵測邏輯模組化，提升後續擴充性與維護性。
- 撰寫 JUnit 5 單元測試並整合 GitHub Actions CI，自動執行 Maven Test。
- 支援 Markdown / JSON 報告輸出，可作為 SOC Log Analysis 與資安事件初步判斷工具。
```

## 面試說明重點

可以這樣介紹：

> 這個專案是我用 Java 實作的防禦型資安日誌分析工具，主要目標是模擬 SOC 或資安維運工作中，如何從大量日誌中找出可疑行為。專案中我設計了 Rule Engine，讓不同偵測規則可以獨立維護，例如暴力破解登入、Web Injection Payload、掃描工具特徵等。除了功能本身，也有加入單元測試與 GitHub Actions，展現我對程式品質與 CI 流程的理解。

## 注意事項

此專案僅用於防禦型資安學習與日誌分析示範，不包含攻擊、自動化入侵或未授權測試功能。
