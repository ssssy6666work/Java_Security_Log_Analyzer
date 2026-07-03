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

public final class BruteForceRule implements SecurityRule {
    private final int failedLoginThreshold;
    private final Duration timeWindow;

    public BruteForceRule(int failedLoginThreshold, Duration timeWindow) {
        if (failedLoginThreshold < 2) {
            throw new IllegalArgumentException("failedLoginThreshold must be at least 2");
        }
        if (timeWindow == null || timeWindow.isNegative() || timeWindow.isZero()) {
            throw new IllegalArgumentException("timeWindow must be positive");
        }
        this.failedLoginThreshold = failedLoginThreshold;
        this.timeWindow = timeWindow;
    }

    @Override
    public String name() {
        return "Brute Force Login Detection";
    }

    @Override
    public List<DetectionResult> analyze(List<LogEntry> entries) {
        Map<String, List<LogEntry>> failedByIp = new HashMap<>();
        for (LogEntry entry : entries) {
            if ("LOGIN_FAILED".equalsIgnoreCase(entry.eventType())) {
                failedByIp.computeIfAbsent(entry.sourceIp(), key -> new ArrayList<>()).add(entry);
            }
        }

        List<DetectionResult> results = new ArrayList<>();
        Set<String> alreadyReported = new HashSet<>();

        for (Map.Entry<String, List<LogEntry>> group : failedByIp.entrySet()) {
            List<LogEntry> failedLogins = group.getValue();
            failedLogins.sort(Comparator.comparing(LogEntry::timestamp));

            for (int start = 0; start < failedLogins.size(); start++) {
                Instant windowStart = failedLogins.get(start).timestamp();
                Instant windowEnd = windowStart.plus(timeWindow);

                List<LogEntry> withinWindow = new ArrayList<>();
                for (int current = start; current < failedLogins.size(); current++) {
                    LogEntry candidate = failedLogins.get(current);
                    if (!candidate.timestamp().isAfter(windowEnd)) {
                        withinWindow.add(candidate);
                    }
                }

                if (withinWindow.size() >= failedLoginThreshold && alreadyReported.add(group.getKey())) {
                    List<String> evidence = new ArrayList<>();
                    for (int index = 0; index < withinWindow.size() && index < 5; index++) {
                        evidence.add(withinWindow.get(index).compact());
                    }
                    results.add(new DetectionResult(
                            name(),
                            Severity.HIGH,
                            "IP " + group.getKey() + " generated " + withinWindow.size()
                                    + " failed logins within " + timeWindow.toMinutes() + " minutes.",
                            evidence
                    ));
                    break;
                }
            }
        }

        return results;
    }
}
