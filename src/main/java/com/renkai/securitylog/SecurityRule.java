package com.renkai.securitylog;

import java.util.List;

/**
 * 所有安全日誌偵測規則共同遵守的介面。
 *
 * 新增規則時只要實作規則名稱與分析方法，就能交由 RuleEngine 統一執行。
 */
public interface SecurityRule {
    // 回傳規則名稱，供報告顯示與結果排序使用。
    String name();

    // 分析日誌並回傳這項規則找到的所有偵測結果。
    List<DetectionResult> analyze(List<LogEntry> entries);
}
