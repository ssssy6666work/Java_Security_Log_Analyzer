package com.renkai.securitylog;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Web 注入攻擊特徵偵測規則。
 *
 * 使用正規表示式檢查日誌訊息中是否出現 SQL Injection、XSS、
 * Path Traversal 或敏感檔案存取等常見攻擊字串。
 */
public final class InjectionPatternRule implements SecurityRule {
    // 集中定義需要偵測的可疑字串，(?i) 代表比對時不區分英文大小寫。
    private static final Pattern SUSPICIOUS_PATTERN = Pattern.compile(
            "(?i)(\\bUNION\\s+SELECT\\b|\\bOR\\s+['\"]?1['\"]?\\s*=\\s*['\"]?1|<script|\\.\\./|/etc/passwd|\\bDROP\\s+TABLE\\b|\\bSELECT\\s+.+\\bFROM\\b)"
    );

    @Override
    // 回傳這項安全規則的顯示名稱。
    public String name() {
        return "Web Injection Pattern Detection";
    }

    @Override
    /**
     * 逐筆檢查日誌訊息是否符合可疑注入攻擊特徵。
     */
    public List<DetectionResult> analyze(List<LogEntry> entries) {
        // 用來收集所有符合條件的偵測結果。
        List<DetectionResult> results = new ArrayList<>();
        // 每一筆日誌都會個別進行特徵比對。
        for (LogEntry entry : entries) {
            // find() 只要在訊息任一位置找到符合內容，就視為可疑事件。
            if (SUSPICIOUS_PATTERN.matcher(entry.message()).find()) {
                // 每一筆符合的日誌都建立一筆 HIGH 等級偵測結果。
                results.add(new DetectionResult(
                        name(),
                        Severity.HIGH,
                        "Suspicious web payload from " + entry.sourceIp() + " user=" + entry.username(),
                        Collections.singletonList(entry.compact())
                ));
            }
        }
        // 回傳所有偵測到的 Web 注入攻擊事件。
        return results;
    }
}
