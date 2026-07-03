package com.renkai.securitylog;

import java.util.List;

public interface SecurityRule {
    String name();

    List<DetectionResult> analyze(List<LogEntry> entries);
}
