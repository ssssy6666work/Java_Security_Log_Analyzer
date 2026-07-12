package com.renkai.securitylog;

import java.util.List;

/**
 * 將偵測結果轉換成可閱讀或可供程式處理的報告格式。
 *
 * 目前支援 Markdown 與 JSON 兩種輸出格式。
 */
public final class ReportFormatter {
    // 此類別只提供靜態格式化方法，不需要建立物件。
    private ReportFormatter() {
    }

    /**
     * 將偵測結果轉換成 Markdown 報告。
     */
    public static String toMarkdown(List<DetectionResult> results) {
        // 使用 StringBuilder 逐步組合報告內容，避免大量字串相加。
        StringBuilder builder = new StringBuilder();
        builder.append("# Security Log Analysis Report\n\n");
        builder.append("Total findings: ").append(results.size()).append("\n\n");

        // 沒有任何發現時，直接輸出無可疑活動的訊息。
        if (results.isEmpty()) {
            builder.append("No suspicious activity detected.\n");
            return builder.toString();
        }

        // 逐筆建立包含編號、規則、嚴重程度、摘要與證據的報告區塊。
        for (int i = 0; i < results.size(); i++) {
            DetectionResult result = results.get(i);
            builder.append("## ").append(i + 1).append(". ").append(result.ruleName()).append("\n\n");
            builder.append("- Severity: **").append(result.severity()).append("**\n");
            builder.append("- Summary: ").append(result.summary()).append("\n");
            // 只有在存在證據時才建立 Evidence 區段。
            if (!result.evidence().isEmpty()) {
                builder.append("- Evidence:\n");
                // 每一筆證據使用 Markdown 行內程式碼格式呈現。
                for (String evidence : result.evidence()) {
                    builder.append("  - `").append(escapeBackticks(evidence)).append("`\n");
                }
            }
            builder.append("\n");
        }

        // 回傳完整的 Markdown 文字。
        return builder.toString();
    }

    /**
     * 將偵測結果轉換成 JSON 報告。
     */
    public static String toJson(List<DetectionResult> results) {
        // 手動組合 JSON 內容，並在輸出文字欄位前進行必要的跳脫處理。
        StringBuilder builder = new StringBuilder();
        builder.append("{\n  \"totalFindings\": ").append(results.size()).append(",\n  \"findings\": [\n");
        // 逐筆輸出 findings 陣列中的 JSON 物件。
        for (int i = 0; i < results.size(); i++) {
            DetectionResult result = results.get(i);
            builder.append("    {\n");
            builder.append("      \"ruleName\": \"").append(jsonEscape(result.ruleName())).append("\",\n");
            builder.append("      \"severity\": \"").append(result.severity()).append("\",\n");
            builder.append("      \"summary\": \"").append(jsonEscape(result.summary())).append("\",\n");
            builder.append("      \"evidence\": [");
            // 逐筆輸出 evidence 陣列，並正確處理項目之間的逗號。
            for (int j = 0; j < result.evidence().size(); j++) {
                if (j > 0) {
                    builder.append(", ");
                }
                builder.append("\"").append(jsonEscape(result.evidence().get(j))).append("\"");
            }
            builder.append("]\n");
            builder.append("    }");
            // 最後一筆 finding 後方不可再加逗號。
            if (i < results.size() - 1) {
                builder.append(",");
            }
            builder.append("\n");
        }
        // 補上 JSON 結尾並回傳完整文字。
        builder.append("  ]\n}\n");
        return builder.toString();
    }

    // 避免證據中的反引號破壞 Markdown 行內程式碼格式。
    private static String escapeBackticks(String value) {
        return value.replace("`", "'");
    }

    // 將 JSON 特殊字元轉成合法的跳脫序列。
    private static String jsonEscape(String value) {
        return value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
