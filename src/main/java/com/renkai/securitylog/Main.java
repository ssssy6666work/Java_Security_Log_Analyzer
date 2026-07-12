package com.renkai.securitylog;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * 安全日誌分析器的程式進入點。
 *
 * 負責解析命令列參數、讀取日誌、執行安全規則，最後輸出 Markdown 或 JSON 報告。
 */
public final class Main {
    // Main 只作為程式進入點使用，不需要建立物件。
    private Main() {
    }

    /**
     * 程式主流程。
     *
     * @param args 命令列參數
     */
    public static void main(String[] args) throws IOException {
        // 將命令列參數轉換成程式可使用的設定物件。
        CliConfig config = CliConfig.parse(args);
        // 沒有輸入檔案或指定 --help 時，只顯示操作說明後結束。
        if (config.showHelp()) {
            printUsage();
            return;
        }

        // 讀取並解析指定的安全日誌檔案。
        List<LogEntry> entries = LogParser.parseFile(config.inputFile());
        // 建立本次分析要執行的所有安全規則。
        List<SecurityRule> rules = new ArrayList<SecurityRule>();
        rules.add(new BruteForceRule(config.failedThreshold(), Duration.ofMinutes(config.windowMinutes())));
        rules.add(new InjectionPatternRule());
        rules.add(new SuspiciousToolRule());

        // 規則引擎會依序執行所有規則並彙整偵測結果。
        RuleEngine engine = new RuleEngine(rules);
        List<DetectionResult> results = engine.analyze(entries);
        // 根據 --format 的設定，將結果轉換成 JSON 或 Markdown。
        String report = "json".equalsIgnoreCase(config.format())
                ? ReportFormatter.toJson(results)
                : ReportFormatter.toMarkdown(results);

        // 未指定輸出檔案時直接顯示於終端機，否則寫入指定檔案。
        if (config.outputFile() == null) {
            System.out.println(report);
        } else {
            Files.write(config.outputFile(), report.getBytes(StandardCharsets.UTF_8));
            System.out.println("Report written to: " + config.outputFile());
        }
    }

    // 顯示程式使用方式、可用選項與日誌格式範例。
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

    /**
     * 保存解析後的命令列設定。
     *
     * 這個內部類別只供 Main 使用，避免命令列處理細節散落在主流程中。
     */
    private static final class CliConfig {
        // 要分析的日誌檔案路徑。
        private final Path inputFile;
        // 暴力破解規則的登入失敗次數門檻。
        private final int failedThreshold;
        // 暴力破解規則的時間視窗，單位為分鐘。
        private final int windowMinutes;
        // 報告格式，目前支援 markdown 與 json。
        private final String format;
        // 報告輸出路徑；null 代表輸出到終端機。
        private final Path outputFile;
        // 是否只顯示說明文字。
        private final boolean showHelp;

        // 將所有解析完成的設定保存到不可變欄位中。
        private CliConfig(Path inputFile, int failedThreshold, int windowMinutes,
                          String format, Path outputFile, boolean showHelp) {
            this.inputFile = inputFile;
            this.failedThreshold = failedThreshold;
            this.windowMinutes = windowMinutes;
            this.format = format;
            this.outputFile = outputFile;
            this.showHelp = showHelp;
        }

        // 取得輸入日誌檔案。
        Path inputFile() {
            return inputFile;
        }

        // 取得登入失敗次數門檻。
        int failedThreshold() {
            return failedThreshold;
        }

        // 取得時間視窗分鐘數。
        int windowMinutes() {
            return windowMinutes;
        }

        // 取得報告格式。
        String format() {
            return format;
        }

        // 取得報告輸出檔案。
        Path outputFile() {
            return outputFile;
        }

        // 取得是否顯示說明文字。
        boolean showHelp() {
            return showHelp;
        }

        /**
         * 解析命令列參數並建立設定物件。
         */
        static CliConfig parse(String[] args) {
            // 沒有參數或包含 --help 時，使用預設值建立說明模式設定。
            if (args.length == 0 || contains(args, "--help")) {
                return new CliConfig(null, 5, 10, "markdown", null, true);
            }

            // 第一個參數固定視為要分析的日誌檔案。
            Path inputFile = Paths.get(args[0]);
            // 以下是所有選項的預設值。
            int failedThreshold = 5;
            int windowMinutes = 10;
            String format = "markdown";
            Path outputFile = null;

            // 從第二個參數開始，逐一判斷與解析選項。
            for (int i = 1; i < args.length; i++) {
                String arg = args[i];
                // 每個需要值的選項都先取得下一個參數，再進行格式驗證。
                if ("--failed-threshold".equals(arg)) {
                    failedThreshold = parsePositiveInt(nextValue(args, ++i, arg), arg);
                } else if ("--window-minutes".equals(arg)) {
                    windowMinutes = parsePositiveInt(nextValue(args, ++i, arg), arg);
                } else if ("--format".equals(arg)) {
                    format = parseFormat(nextValue(args, ++i, arg));
                } else if ("--output".equals(arg)) {
                    outputFile = Paths.get(nextValue(args, ++i, arg));
                } else {
                    // 不接受未定義的命令列選項，避免使用者誤輸入卻未察覺。
                    throw new IllegalArgumentException("Unknown option: " + arg);
                }
            }

            // 所有參數解析完成後，建立正式執行模式的設定物件。
            return new CliConfig(inputFile, failedThreshold, windowMinutes, format, outputFile, false);
        }

        // 檢查參數陣列中是否包含指定文字。
        private static boolean contains(String[] args, String expected) {
            for (String arg : args) {
                if (expected.equals(arg)) {
                    return true;
                }
            }
            return false;
        }

        // 取得選項後方的值；若不存在則立即回報缺少參數。
        private static String nextValue(String[] args, int index, String option) {
            if (index >= args.length) {
                throw new IllegalArgumentException("Missing value for " + option);
            }
            return args[index];
        }

        // 將文字轉換成正整數，供門檻與分鐘數選項使用。
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

        // 驗證報告格式只允許 markdown 或 json。
        private static String parseFormat(String value) {
            if (!"markdown".equalsIgnoreCase(value) && !"json".equalsIgnoreCase(value)) {
                throw new IllegalArgumentException("format must be markdown or json");
            }
            return value;
        }
    }
}
