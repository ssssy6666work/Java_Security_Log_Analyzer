package com.renkai.securitylog;

import java.time.Instant;
import java.util.Objects;

/**
 * 表示從安全日誌中解析出來的一筆事件資料。
 *
 * 物件建立後各欄位不再改變，方便安全規則穩定地讀取與分析。
 */
public final class LogEntry {
    // 事件發生時間，使用 UTC 時間格式的 Instant 儲存。
    private final Instant timestamp;
    // 日誌等級，例如 INFO、WARN 或 ERROR。
    private final String level;
    // 產生事件的來源 IP 位址。
    private final String sourceIp;
    // 與事件相關的使用者名稱。
    private final String username;
    // 事件類型，例如 LOGIN_FAILED。
    private final String eventType;
    // 日誌中額外記錄的詳細訊息。
    private final String message;

    /**
     * 建立一筆日誌事件，並驗證必要欄位。
     */
    public LogEntry(Instant timestamp, String level, String sourceIp, String username, String eventType, String message) {
        this.timestamp = Objects.requireNonNull(timestamp, "timestamp");
        this.level = requireText(level, "level");
        this.sourceIp = requireText(sourceIp, "sourceIp");
        this.username = requireText(username, "username");
        this.eventType = requireText(eventType, "eventType");
        // 訊息允許沒有內容，因此 null 會被統一轉成空字串。
        this.message = message == null ? "" : message;
    }

    // 取得事件發生時間。
    public Instant timestamp() {
        return timestamp;
    }

    // 取得日誌等級。
    public String level() {
        return level;
    }

    // 取得來源 IP。
    public String sourceIp() {
        return sourceIp;
    }

    // 取得使用者名稱。
    public String username() {
        return username;
    }

    // 取得事件類型。
    public String eventType() {
        return eventType;
    }

    // 取得事件詳細訊息。
    public String message() {
        return message;
    }

    // 將主要欄位組合成單行文字，方便放入偵測報告的證據區。
    public String compact() {
        return timestamp + " " + sourceIp + " " + username + " " + eventType + " " + message;
    }

    // 驗證必要文字欄位不可為 null、空字串或只包含空白。
    private static String requireText(String value, String fieldName) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
        return value;
    }
}
