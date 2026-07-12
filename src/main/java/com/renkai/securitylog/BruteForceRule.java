package com.renkai.securitylog;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 暴力破解登入偵測規則。
 *
 * 此規則會依來源 IP 彙整登入失敗紀錄，並檢查指定時間範圍內的失敗次數
 * 是否達到門檻。達到門檻時，會產生一筆 HIGH 等級的偵測結果。
 */
public final class BruteForceRule implements SecurityRule {
    // 在指定時間範圍內，登入失敗次數必須達到的門檻。
    private final int failedLoginThreshold;
    // 用來判斷暴力破解行為的時間範圍。
    private final Duration timeWindow;

    /**
     * 建立暴力破解偵測規則。
     *
     * @param failedLoginThreshold 登入失敗次數門檻
     * @param timeWindow           統計登入失敗次數的時間範圍
     */
    public BruteForceRule(int failedLoginThreshold, Duration timeWindow) {
        // 門檻至少要是 2，否則無法合理代表重複嘗試登入。
        if (failedLoginThreshold < 2) {
            throw new IllegalArgumentException("failedLoginThreshold must be at least 2");
        }
        // 時間範圍不可為 null、負數或零。
        if (timeWindow == null || timeWindow.isNegative() || timeWindow.isZero()) {
            throw new IllegalArgumentException("timeWindow must be positive");
        }
        this.failedLoginThreshold = failedLoginThreshold;
        this.timeWindow = timeWindow;
    }

    @Override
    // 回傳這項安全規則的顯示名稱。
    public String name() {
        return "Brute Force Login Detection";
    }

    @Override
    /**
     * 分析所有日誌，尋找可能的暴力破解登入行為。
     *
     * @param entries 已解析完成的日誌資料
     * @return 此規則找到的偵測結果
     */
    public List<DetectionResult> analyze(List<LogEntry> entries) {
        // 將 LOGIN_FAILED 事件依照來源 IP 分組。
        Map<String, List<LogEntry>> failedByIp = new HashMap<>();
        for (LogEntry entry : entries) {
            if ("LOGIN_FAILED".equalsIgnoreCase(entry.eventType())) {
                failedByIp.computeIfAbsent(entry.sourceIp(), key -> new ArrayList<>()).add(entry);
            }
        }

        // 儲存偵測結果，並記錄已回報過的 IP，避免同一個 IP 重複產生警告。
        List<DetectionResult> results = new ArrayList<>();
        Set<String> alreadyReported = new HashSet<>();

        // 逐一分析每個來源 IP 的登入失敗紀錄。
        for (Map.Entry<String, List<LogEntry>> group : failedByIp.entrySet()) {
            List<LogEntry> failedLogins = group.getValue();
            // 先依時間排序，才能正確計算時間視窗。
            failedLogins.sort(Comparator.comparing(LogEntry::timestamp));

            // 以每一筆登入失敗紀錄作為時間視窗的起點。
            for (int start = 0; start < failedLogins.size(); start++) {
                // 計算目前時間視窗的開始與結束時間。
                Instant windowStart = failedLogins.get(start).timestamp();
                Instant windowEnd = windowStart.plus(timeWindow);

                // 收集落在目前時間視窗內的登入失敗紀錄。
                List<LogEntry> withinWindow = new ArrayList<>();
                for (int current = start; current < failedLogins.size(); current++) {
                    LogEntry candidate = failedLogins.get(current);
                    if (!candidate.timestamp().isAfter(windowEnd)) {
                        withinWindow.add(candidate);
                    }
                }

                // 失敗次數達到門檻，而且此 IP 尚未被回報時，建立偵測結果。
                if (withinWindow.size() >= failedLoginThreshold && alreadyReported.add(group.getKey())) {
                    // 最多保留前 5 筆日誌作為報告證據，避免輸出內容過長。
                    List<String> evidence = new ArrayList<>();
                    for (int index = 0; index < withinWindow.size() && index < 5; index++) {
                        evidence.add(withinWindow.get(index).compact());
                    }
                    // 將偵測規則名稱、嚴重程度、摘要與證據封裝成結果物件。
                    results.add(new DetectionResult(
                            name(),
                            Severity.HIGH,
                            "IP " + group.getKey() + " generated " + withinWindow.size()
                                    + " failed logins within " + timeWindow.toMinutes() + " minutes.",
                            evidence
                    ));
                    break;
                    // 同一個 IP 只需要回報一次，完成後離開目前 IP 的時間視窗迴圈。
                }
            }
        }

        // 回傳這項規則找到的所有暴力破解事件。
        return results;
    }
}
