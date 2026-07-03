package com.renkai.securitylog;

import java.util.List;

public final class ReportFormatter {
    private ReportFormatter() {
    }

    public static String toMarkdown(List<DetectionResult> results) {
        StringBuilder builder = new StringBuilder();
        builder.append("# Security Log Analysis Report\n\n");
        builder.append("Total findings: ").append(results.size()).append("\n\n");

        if (results.isEmpty()) {
            builder.append("No suspicious activity detected.\n");
            return builder.toString();
        }

        for (int i = 0; i < results.size(); i++) {
            DetectionResult result = results.get(i);
            builder.append("## ").append(i + 1).append(". ").append(result.ruleName()).append("\n\n");
            builder.append("- Severity: **").append(result.severity()).append("**\n");
            builder.append("- Summary: ").append(result.summary()).append("\n");
            if (!result.evidence().isEmpty()) {
                builder.append("- Evidence:\n");
                for (String evidence : result.evidence()) {
                    builder.append("  - `").append(escapeBackticks(evidence)).append("`\n");
                }
            }
            builder.append("\n");
        }

        return builder.toString();
    }

    public static String toJson(List<DetectionResult> results) {
        StringBuilder builder = new StringBuilder();
        builder.append("{\n  \"totalFindings\": ").append(results.size()).append(",\n  \"findings\": [\n");
        for (int i = 0; i < results.size(); i++) {
            DetectionResult result = results.get(i);
            builder.append("    {\n");
            builder.append("      \"ruleName\": \"").append(jsonEscape(result.ruleName())).append("\",\n");
            builder.append("      \"severity\": \"").append(result.severity()).append("\",\n");
            builder.append("      \"summary\": \"").append(jsonEscape(result.summary())).append("\",\n");
            builder.append("      \"evidence\": [");
            for (int j = 0; j < result.evidence().size(); j++) {
                if (j > 0) {
                    builder.append(", ");
                }
                builder.append("\"").append(jsonEscape(result.evidence().get(j))).append("\"");
            }
            builder.append("]\n");
            builder.append("    }");
            if (i < results.size() - 1) {
                builder.append(",");
            }
            builder.append("\n");
        }
        builder.append("  ]\n}\n");
        return builder.toString();
    }

    private static String escapeBackticks(String value) {
        return value.replace("`", "'");
    }

    private static String jsonEscape(String value) {
        return value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
