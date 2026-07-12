package com.renkai.securitylog;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 測試 RuleEngine 是否能執行多個資安偵測規則，
 * 並正確回傳暴力破解與網頁注入攻擊的偵測結果。
 */
class RuleEngineTest {
    /**
     * 建立包含登入失敗與注入攻擊特徵的測試日誌，
     * 驗證規則引擎可以同時偵測兩種資安事件。
     */
    @Test
    void detectBruteForceAndInjection() {
        // 建立用來存放測試日誌資料的清單。
        List<LogEntry> entries = new ArrayList<LogEntry>();
        // 加入同一個 IP 在短時間內連續登入失敗的第一筆日誌。
        entries.add(LogParser.parseLine("2026-07-04T10:00:00Z INFO 203.0.113.10 alice LOGIN_FAILED Invalid", 1));
        // 加入同一個 IP 在短時間內連續登入失敗的第二筆日誌。
        entries.add(LogParser.parseLine("2026-07-04T10:01:00Z INFO 203.0.113.10 alice LOGIN_FAILED Invalid", 2));
        // 加入同一個 IP 在短時間內連續登入失敗的第三筆日誌。
        entries.add(LogParser.parseLine("2026-07-04T10:02:00Z INFO 203.0.113.10 alice LOGIN_FAILED Invalid", 3));
        // 加入具有 SQL Injection 特徵的 HTTP 請求日誌。
        entries.add(LogParser.parseLine("2026-07-04T10:03:00Z WARN 198.51.100.23 guest HTTP_REQUEST GET /?id=1' OR '1'='1", 4));

        // 建立規則清單，準備交給規則引擎執行。
        List<SecurityRule> rules = new ArrayList<SecurityRule>();
        // 設定暴力破解規則：5 分鐘內登入失敗達 3 次即觸發。
        rules.add(new BruteForceRule(3, Duration.ofMinutes(5)));
        // 加入網頁注入攻擊特徵偵測規則。
        rules.add(new InjectionPatternRule());
        // 使用上述規則建立規則引擎。
        RuleEngine engine = new RuleEngine(rules);

        // 執行規則分析並取得所有偵測結果。
        List<DetectionResult> results = engine.analyze(entries);

        // 確認總共偵測到兩筆資安事件。
        assertEquals(2, results.size());
        // 確認結果中包含暴力破解偵測。
        assertTrue(results.stream().anyMatch(result -> result.ruleName().contains("Brute Force")));
        // 確認結果中包含注入攻擊偵測。
        assertTrue(results.stream().anyMatch(result -> result.ruleName().contains("Injection")));
    }
}
