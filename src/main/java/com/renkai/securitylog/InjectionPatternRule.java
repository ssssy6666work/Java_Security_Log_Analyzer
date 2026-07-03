package com.renkai.securitylog;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

public final class InjectionPatternRule implements SecurityRule {
    private static final Pattern SUSPICIOUS_PATTERN = Pattern.compile(
            "(?i)(\\bUNION\\s+SELECT\\b|\\bOR\\s+['\"]?1['\"]?\\s*=\\s*['\"]?1|<script|\\.\\./|/etc/passwd|\\bDROP\\s+TABLE\\b|\\bSELECT\\s+.+\\bFROM\\b)"
    );

    @Override
    public String name() {
        return "Web Injection Pattern Detection";
    }

    @Override
    public List<DetectionResult> analyze(List<LogEntry> entries) {
        List<DetectionResult> results = new ArrayList<>();
        for (LogEntry entry : entries) {
            if (SUSPICIOUS_PATTERN.matcher(entry.message()).find()) {
                results.add(new DetectionResult(
                        name(),
                        Severity.HIGH,
                        "Suspicious web payload from " + entry.sourceIp() + " user=" + entry.username(),
                        Collections.singletonList(entry.compact())
                ));
            }
        }
        return results;
    }
}
