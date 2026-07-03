package com.renkai.securitylog;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RuleEngineTest {
    @Test
    void detectBruteForceAndInjection() {
        List<LogEntry> entries = new ArrayList<LogEntry>();
        entries.add(LogParser.parseLine("2026-07-04T10:00:00Z INFO 203.0.113.10 alice LOGIN_FAILED Invalid", 1));
        entries.add(LogParser.parseLine("2026-07-04T10:01:00Z INFO 203.0.113.10 alice LOGIN_FAILED Invalid", 2));
        entries.add(LogParser.parseLine("2026-07-04T10:02:00Z INFO 203.0.113.10 alice LOGIN_FAILED Invalid", 3));
        entries.add(LogParser.parseLine("2026-07-04T10:03:00Z WARN 198.51.100.23 guest HTTP_REQUEST GET /?id=1' OR '1'='1", 4));

        List<SecurityRule> rules = new ArrayList<SecurityRule>();
        rules.add(new BruteForceRule(3, Duration.ofMinutes(5)));
        rules.add(new InjectionPatternRule());
        RuleEngine engine = new RuleEngine(rules);

        List<DetectionResult> results = engine.analyze(entries);

        assertEquals(2, results.size());
        assertTrue(results.stream().anyMatch(result -> result.ruleName().contains("Brute Force")));
        assertTrue(results.stream().anyMatch(result -> result.ruleName().contains("Injection")));
    }
}
