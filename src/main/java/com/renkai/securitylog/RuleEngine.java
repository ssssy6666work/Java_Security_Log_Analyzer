package com.renkai.securitylog;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public final class RuleEngine {
    private final List<SecurityRule> rules;

    public RuleEngine(List<SecurityRule> rules) {
        this.rules = Collections.unmodifiableList(new ArrayList<SecurityRule>(rules));
    }

    public List<DetectionResult> analyze(List<LogEntry> entries) {
        List<DetectionResult> results = new ArrayList<>();
        for (SecurityRule rule : rules) {
            results.addAll(rule.analyze(entries));
        }
        results.sort(Comparator
                .comparing(DetectionResult::severity).reversed()
                .thenComparing(DetectionResult::ruleName)
                .thenComparing(DetectionResult::summary));
        return results;
    }
}
