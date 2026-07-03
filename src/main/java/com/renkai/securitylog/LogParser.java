package com.renkai.securitylog;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public final class LogParser {
    private LogParser() {
    }

    /**
     * Expected format:
     * 2026-07-04T10:00:00Z INFO 203.0.113.10 alice LOGIN_FAILED Invalid password
     */
    public static List<LogEntry> parseFile(Path path) throws IOException {
        List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
        List<LogEntry> entries = new ArrayList<>();

        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i).trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            entries.add(parseLine(line, i + 1));
        }

        return entries;
    }

    public static LogEntry parseLine(String line, int lineNumber) {
        String[] parts = line.split("\\s+", 6);
        if (parts.length < 5) {
            throw new IllegalArgumentException("Invalid log format at line " + lineNumber + ": " + line);
        }

        String message = parts.length == 6 ? parts[5] : "";
        try {
            return new LogEntry(
                    Instant.parse(parts[0]),
                    parts[1],
                    parts[2],
                    parts[3],
                    parts[4],
                    message
            );
        } catch (RuntimeException ex) {
            throw new IllegalArgumentException("Invalid log data at line " + lineNumber + ": " + line, ex);
        }
    }
}
