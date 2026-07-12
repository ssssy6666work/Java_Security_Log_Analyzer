package com.renkai.securitylog;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * 可疑資安掃描工具特徵偵測規則。
 *
 * 當日誌訊息中出現常見掃描器、弱點掃描工具或目錄掃描工具名稱時，
 * 會產生一筆 MEDIUM 等級的偵測結果。
 */
public final class SuspiciousToolRule implements SecurityRule {
    // 需要比對的常見資安掃描與測試工具關鍵字。
    private static final List<String> TOOL_KEYWORDS = Arrays.asList(
            "sqlmap",
            "nikto",
            "nmap",
            "masscan",
            "gobuster",
            "dirbuster",
            "wpscan",
	    "acunetix",
	    "nessus",
	    "openvas",
	    "zap"
    );

    @Override
    // 回傳這項安全規則的顯示名稱。
    public String name() {
        return "Suspicious Security Tool Signature Detection";
    }

    @Override
    /**
     * 逐筆檢查日誌訊息中是否包含可疑工具名稱。
     */
    public List<DetectionResult> analyze(List<LogEntry> entries) {
        // 收集所有符合條件的偵測結果。
        List<DetectionResult> results = new ArrayList<>();
        // 逐筆分析日誌內容。
        for (LogEntry entry : entries) {
            // 統一轉成小寫，讓工具名稱比對不受英文大小寫影響。
            String normalized = entry.message().toLowerCase(Locale.ROOT);
            // 將訊息與每一個工具關鍵字進行比對。
            for (String keyword : TOOL_KEYWORDS) {
                // contains() 只要訊息中包含關鍵字就視為可能的工具特徵。
                if (normalized.contains(keyword)) {
                    // 建立 MEDIUM 等級結果，並保留原始日誌作為證據。
                    results.add(new DetectionResult(
                            name(),
                            Severity.MEDIUM,
                            "Possible scanner/tool signature detected: " + keyword + " from " + entry.sourceIp(),
                            Collections.singletonList(entry.compact())
                    ));
                    // 同一筆日誌找到一個工具名稱後即可停止，避免重複回報。
                    break;
                }
            }
        }
        // 回傳所有可疑工具特徵事件。
        return results;
    }
}
