package com.renkai.securitylog;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

public final class SuspiciousToolRule implements SecurityRule {
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
    public String name() {
        return "Suspicious Security Tool Signature Detection";
    }

    @Override
    public List<DetectionResult> analyze(List<LogEntry> entries) {
        List<DetectionResult> results = new ArrayList<>();
        for (LogEntry entry : entries) {
            String normalized = entry.message().toLowerCase(Locale.ROOT);
            for (String keyword : TOOL_KEYWORDS) {
                if (normalized.contains(keyword)) {
                    results.add(new DetectionResult(
                            name(),
                            Severity.MEDIUM,
                            "Possible scanner/tool signature detected: " + keyword + " from " + entry.sourceIp(),
                            Collections.singletonList(entry.compact())
                    ));
                    break;
                }
            }
        }
        return results;
    }
}
