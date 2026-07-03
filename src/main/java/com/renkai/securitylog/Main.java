package com.renkai.securitylog;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

public final class Main {
    private Main() {
    }

    public static void main(String[] args) throws IOException {
        CliConfig config = CliConfig.parse(args);
        if (config.showHelp()) {
            printUsage();
            return;
        }

        List<LogEntry> entries = LogParser.parseFile(config.inputFile());
        List<SecurityRule> rules = new ArrayList<SecurityRule>();
        rules.add(new BruteForceRule(config.failedThreshold(), Duration.ofMinutes(config.windowMinutes())));
        rules.add(new InjectionPatternRule());
        rules.add(new SuspiciousToolRule());

        RuleEngine engine = new RuleEngine(rules);
        List<DetectionResult> results = engine.analyze(entries);
        String report = "json".equalsIgnoreCase(config.format())
                ? ReportFormatter.toJson(results)
                : ReportFormatter.toMarkdown(results);

        if (config.outputFile() == null) {
            System.out.println(report);
        } else {
            Files.write(config.outputFile(), report.getBytes(StandardCharsets.UTF_8));
            System.out.println("Report written to: " + config.outputFile());
        }
    }

    private static void printUsage() {
        System.out.println(
                "Java Security Log Analyzer\n\n"
                        + "Usage:\n"
                        + "  java -jar target/security-log-analyzer-1.0.0.jar <log-file> [options]\n\n"
                        + "Options:\n"
                        + "  --failed-threshold <number>  Failed login count threshold. Default: 5\n"
                        + "  --window-minutes <number>    Time window for failed logins. Default: 10\n"
                        + "  --format <markdown|json>     Report format. Default: markdown\n"
                        + "  --output <file>              Write report to file instead of console\n"
                        + "  --help                       Show this help message\n\n"
                        + "Log format:\n"
                        + "  2026-07-04T10:00:00Z INFO 203.0.113.10 alice LOGIN_FAILED Invalid password\n"
        );
    }

    private static final class CliConfig {
        private final Path inputFile;
        private final int failedThreshold;
        private final int windowMinutes;
        private final String format;
        private final Path outputFile;
        private final boolean showHelp;

        private CliConfig(Path inputFile, int failedThreshold, int windowMinutes,
                          String format, Path outputFile, boolean showHelp) {
            this.inputFile = inputFile;
            this.failedThreshold = failedThreshold;
            this.windowMinutes = windowMinutes;
            this.format = format;
            this.outputFile = outputFile;
            this.showHelp = showHelp;
        }

        Path inputFile() {
            return inputFile;
        }

        int failedThreshold() {
            return failedThreshold;
        }

        int windowMinutes() {
            return windowMinutes;
        }

        String format() {
            return format;
        }

        Path outputFile() {
            return outputFile;
        }

        boolean showHelp() {
            return showHelp;
        }

        static CliConfig parse(String[] args) {
            if (args.length == 0 || contains(args, "--help")) {
                return new CliConfig(null, 5, 10, "markdown", null, true);
            }

            Path inputFile = Paths.get(args[0]);
            int failedThreshold = 5;
            int windowMinutes = 10;
            String format = "markdown";
            Path outputFile = null;

            for (int i = 1; i < args.length; i++) {
                String arg = args[i];
                if ("--failed-threshold".equals(arg)) {
                    failedThreshold = parsePositiveInt(nextValue(args, ++i, arg), arg);
                } else if ("--window-minutes".equals(arg)) {
                    windowMinutes = parsePositiveInt(nextValue(args, ++i, arg), arg);
                } else if ("--format".equals(arg)) {
                    format = parseFormat(nextValue(args, ++i, arg));
                } else if ("--output".equals(arg)) {
                    outputFile = Paths.get(nextValue(args, ++i, arg));
                } else {
                    throw new IllegalArgumentException("Unknown option: " + arg);
                }
            }

            return new CliConfig(inputFile, failedThreshold, windowMinutes, format, outputFile, false);
        }

        private static boolean contains(String[] args, String expected) {
            for (String arg : args) {
                if (expected.equals(arg)) {
                    return true;
                }
            }
            return false;
        }

        private static String nextValue(String[] args, int index, String option) {
            if (index >= args.length) {
                throw new IllegalArgumentException("Missing value for " + option);
            }
            return args[index];
        }

        private static int parsePositiveInt(String value, String option) {
            try {
                int parsed = Integer.parseInt(value);
                if (parsed <= 0) {
                    throw new IllegalArgumentException(option + " must be positive");
                }
                return parsed;
            } catch (NumberFormatException ex) {
                throw new IllegalArgumentException(option + " must be a number: " + value, ex);
            }
        }

        private static String parseFormat(String value) {
            if (!"markdown".equalsIgnoreCase(value) && !"json".equalsIgnoreCase(value)) {
                throw new IllegalArgumentException("format must be markdown or json");
            }
            return value;
        }
    }
}
