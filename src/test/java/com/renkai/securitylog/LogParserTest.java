package com.renkai.securitylog;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 測試 LogParser 是否能正確解析日誌字串，
 * 並確認格式錯誤的日誌會拋出預期的例外。
 */
class LogParserTest {
    /**
     * 測試格式正確的日誌資料。
     * 驗證解析後的時間、等級、來源 IP、使用者名稱、
     * 事件類型與訊息內容是否都符合原始字串。
     */
    @Test
    void parseValidLine() {
        // 呼叫 LogParser.parseLine，將一行文字日誌轉換成 LogEntry 物件。
        LogEntry entry = LogParser.parseLine(
                "2026-07-04T10:00:00Z INFO 203.0.113.10 alice LOGIN_FAILED Invalid password",
                1
        );

        // 確認解析後的時間戳記正確。
        assertEquals(Instant.parse("2026-07-04T10:00:00Z"), entry.timestamp());
        // 確認日誌等級正確。
        assertEquals("INFO", entry.level());
        // 確認來源 IP 位址正確。
        assertEquals("203.0.113.10", entry.sourceIp());
        // 確認使用者名稱正確。
        assertEquals("alice", entry.username());
        // 確認事件類型正確。
        assertEquals("LOGIN_FAILED", entry.eventType());
        // 確認日誌訊息內容正確。
        assertEquals("Invalid password", entry.message());
    }

    /**
     * 測試格式不正確的日誌資料。
     * 預期 LogParser 會拋出 IllegalArgumentException。
     */
    @Test
    void rejectInvalidLine() {
        // 確認傳入無效格式時會產生預期的例外。
        assertThrows(IllegalArgumentException.class, () -> LogParser.parseLine("invalid line", 1));
    }
}
