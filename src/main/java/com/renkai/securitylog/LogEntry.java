package com.renkai.securitylog;

import java.time.Instant;
import java.util.Objects;

public final class LogEntry {
    private final Instant timestamp;
    private final String level;
    private final String sourceIp;
    private final String username;
    private final String eventType;
    private final String message;

    public LogEntry(Instant timestamp, String level, String sourceIp, String username, String eventType, String message) {
        this.timestamp = Objects.requireNonNull(timestamp, "timestamp");
        this.level = requireText(level, "level");
        this.sourceIp = requireText(sourceIp, "sourceIp");
        this.username = requireText(username, "username");
        this.eventType = requireText(eventType, "eventType");
        this.message = message == null ? "" : message;
    }

    public Instant timestamp() {
        return timestamp;
    }

    public String level() {
        return level;
    }

    public String sourceIp() {
        return sourceIp;
    }

    public String username() {
        return username;
    }

    public String eventType() {
        return eventType;
    }

    public String message() {
        return message;
    }

    public String compact() {
        return timestamp + " " + sourceIp + " " + username + " " + eventType + " " + message;
    }

    private static String requireText(String value, String fieldName) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
        return value;
    }
}
