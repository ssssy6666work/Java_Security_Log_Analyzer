package com.renkai.securitylog;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * 負責將文字格式的安全日誌轉換成 LogEntry 物件。
 *
 * 此類別只提供靜態方法，不需要建立物件。
 */
public final class LogParser {
    // 私有建構子可防止工具類別被外部程式建立實例。
    private LogParser() {
    }

    /**
     * Expected format:
     * 2026-07-04T10:00:00Z INFO 203.0.113.10 alice LOGIN_FAILED Invalid password
     */
    // 讀取指定檔案，逐行解析成日誌物件清單。
    public static List<LogEntry> parseFile(Path path) throws IOException {
        // 明確使用 UTF-8 編碼，一次讀取檔案中的所有文字行。
        List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
        List<LogEntry> entries = new ArrayList<>();

        // 保留原始行號，發生格式錯誤時可指出問題位置。
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i).trim();
            // 空白行與以 # 開頭的註解行不需要進行分析。
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            // 將有效日誌交給 parseLine() 解析，行號從 1 開始。
            entries.add(parseLine(line, i + 1));
        }

        // 回傳檔案中所有成功解析的日誌。
        return entries;
    }

    /**
     * 解析單行日誌。
     *
     * @param line       日誌文字
     * @param lineNumber 原始檔案中的行號，用於錯誤訊息
     * @return 解析完成的 LogEntry
     */
    public static LogEntry parseLine(String line, int lineNumber) {
        // 最多切成 6 段，讓第 6 段訊息內容可以保留其中的空白。
        String[] parts = line.split("\\s+", 6);
        // 前 5 個欄位為必要資料，數量不足代表格式錯誤。
        if (parts.length < 5) {
            throw new IllegalArgumentException("Invalid log format at line " + lineNumber + ": " + line);
        }

        // 第 6 個欄位不存在時，訊息內容使用空字串。
        String message = parts.length == 6 ? parts[5] : "";
        // 轉換時間與建立 LogEntry 時可能發生格式或資料驗證錯誤。
        try {
            return new LogEntry(
                    Instant.parse(parts[0]),
                    parts[1],
                    parts[2],
                    parts[3],
                    parts[4],
                    message
            );
        // 將底層錯誤包裝成包含行號與原始內容的例外，方便排查。
        } catch (RuntimeException ex) {
            throw new IllegalArgumentException("Invalid log data at line " + lineNumber + ": " + line, ex);
        }
    }
}
