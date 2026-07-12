package com.renkai.securitylog;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * 安全規則執行引擎。
 *
 * 負責依序執行所有 SecurityRule，彙整結果後再依嚴重程度與文字內容排序。
 */
public final class RuleEngine {
    // 保存所有需要執行的安全規則。
    private final List<SecurityRule> rules;

    /**
     * 建立規則引擎。
     */
    public RuleEngine(List<SecurityRule> rules) {
        // 複製傳入清單並設為不可修改，避免外部程式在執行期間變更規則。
        this.rules = Collections.unmodifiableList(new ArrayList<SecurityRule>(rules));
    }

    /**
     * 將同一批日誌交給所有規則分析，並彙整成單一結果清單。
     */
    public List<DetectionResult> analyze(List<LogEntry> entries) {
        // 儲存所有規則回傳的偵測結果。
        List<DetectionResult> results = new ArrayList<>();
        // 每一項規則都會取得完整日誌清單並執行自己的偵測邏輯。
        for (SecurityRule rule : rules) {
            results.addAll(rule.analyze(entries));
        }
        // 先依嚴重程度由高到低排序，再依規則名稱與摘要排序。
        results.sort(Comparator
                .comparing(DetectionResult::severity).reversed()
                .thenComparing(DetectionResult::ruleName)
                .thenComparing(DetectionResult::summary));
        // 回傳排序完成的偵測結果。
        return results;
    }
}
