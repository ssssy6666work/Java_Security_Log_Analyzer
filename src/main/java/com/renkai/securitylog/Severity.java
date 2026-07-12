package com.renkai.securitylog;

/**
 * 安全事件的嚴重程度。
 *
 * 宣告順序也會影響 RuleEngine 使用 reversed() 排序後的優先順序。
 */
public enum Severity {
    // 低風險事件。
    LOW,
    // 中風險事件。
    MEDIUM,
    // 高風險事件。
    HIGH
}
