package com.renkai.securitylog;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class LogParserTest {
    @Test
    void parseValidLine() {
        LogEntry entry = LogParser.parseLine(
                "2026-07-04T10:00:00Z INFO 203.0.113.10 alice LOGIN_FAILED Invalid password",
                1
        );

        assertEquals(Instant.parse("2026-07-04T10:00:00Z"), entry.timestamp());
        assertEquals("INFO", entry.level());
        assertEquals("203.0.113.10", entry.sourceIp());
        assertEquals("alice", entry.username());
        assertEquals("LOGIN_FAILED", entry.eventType());
        assertEquals("Invalid password", entry.message());
    }

    @Test
    void rejectInvalidLine() {
        assertThrows(IllegalArgumentException.class, () -> LogParser.parseLine("invalid line", 1));
    }
}
