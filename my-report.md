# Security Log Analysis Report

Total findings: 5

## 1. Brute Force Login Detection

- Severity: **HIGH**
- Summary: IP 203.0.113.10 generated 5 failed logins within 10 minutes.
- Evidence:
  - `2026-07-04T10:00:00Z 203.0.113.10 alice LOGIN_FAILED Invalid password`
  - `2026-07-04T10:01:00Z 203.0.113.10 alice LOGIN_FAILED Invalid password`
  - `2026-07-04T10:02:00Z 203.0.113.10 alice LOGIN_FAILED Invalid password`
  - `2026-07-04T10:03:00Z 203.0.113.10 alice LOGIN_FAILED Invalid password`
  - `2026-07-04T10:04:00Z 203.0.113.10 alice LOGIN_FAILED Invalid password`

## 2. Web Injection Pattern Detection

- Severity: **HIGH**
- Summary: Suspicious web payload from 198.51.100.23 user=guest
- Evidence:
  - `2026-07-04T10:08:00Z 198.51.100.23 guest HTTP_REQUEST GET /products?id=1' OR '1'='1 Mozilla/5.0`

## 3. Web Injection Pattern Detection

- Severity: **HIGH**
- Summary: Suspicious web payload from 198.51.100.24 user=guest
- Evidence:
  - `2026-07-04T10:09:00Z 198.51.100.24 guest HTTP_REQUEST GET /search?q=<script>alert(1)</script> Mozilla/5.0`

## 4. Suspicious Security Tool Signature Detection

- Severity: **MEDIUM**
- Summary: Possible scanner/tool signature detected: nessus from 198.51.100.88
- Evidence:
  - `2026-07-04T10:30:00Z 198.51.100.88 guest HTTP_REQUEST GET /admin Nessus scanner`

## 5. Suspicious Security Tool Signature Detection

- Severity: **MEDIUM**
- Summary: Possible scanner/tool signature detected: sqlmap from 192.0.2.80
- Evidence:
  - `2026-07-04T10:10:00Z 192.0.2.80 guest HTTP_REQUEST GET /wp-login.php sqlmap/1.7`

