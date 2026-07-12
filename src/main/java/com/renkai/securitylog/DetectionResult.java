package com.renkai.securitylog;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * 表示一筆安全規則的偵測結果。
 *
 * 每筆結果包含觸發的規則名稱、嚴重程度、摘要，以及可供查證的日誌證據。
 */
public final class DetectionResult {
    // 產生這筆結果的安全規則名稱。
    private final String ruleName;
    // 此事件的風險嚴重程度。
    private final Severity severity;
    // 提供給使用者閱讀的事件摘要。
    private final String summary;
    // 支援此判斷的原始日誌內容。
    private final List<String> evidence;

    /**
     * 建立一筆不可變的偵測結果。
     */
    public DetectionResult(String ruleName, Severity severity, String summary, List<String> evidence) {
        this.ruleName = requireText(ruleName, "ruleName");
        this.severity = Objects.requireNonNull(severity, "severity");
        this.summary = requireText(summary, "summary");
        // evidence 為 null 時改用空清單；有資料時則複製並轉成不可修改的清單。
        this.evidence = evidence == null
                ? Collections.<String>emptyList()
                : Collections.unmodifiableList(new ArrayList<String>(evidence));
    }

    // 取得觸發規則名稱。
    public String ruleName() {
        return ruleName;
    }

    // 取得嚴重程度。
    public Severity severity() {
        return severity;
    }

    // 取得事件摘要。
    public String summary() {
        return summary;
    }

    // 取得唯讀的證據清單。
    public List<String> evidence() {
        return evidence;
    }

    // 驗證必要文字欄位不可為 null、空字串或只包含空白。
    private static String requireText(String value, String fieldName) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
        return value;
    }
}
