package com.renkai.securitylog;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

public final class DetectionResult {
    private final String ruleName;
    private final Severity severity;
    private final String summary;
    private final List<String> evidence;

    public DetectionResult(String ruleName, Severity severity, String summary, List<String> evidence) {
        this.ruleName = requireText(ruleName, "ruleName");
        this.severity = Objects.requireNonNull(severity, "severity");
        this.summary = requireText(summary, "summary");
        this.evidence = evidence == null
                ? Collections.<String>emptyList()
                : Collections.unmodifiableList(new ArrayList<String>(evidence));
    }

    public String ruleName() {
        return ruleName;
    }

    public Severity severity() {
        return severity;
    }

    public String summary() {
        return summary;
    }

    public List<String> evidence() {
        return evidence;
    }

    private static String requireText(String value, String fieldName) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
        return value;
    }
}
