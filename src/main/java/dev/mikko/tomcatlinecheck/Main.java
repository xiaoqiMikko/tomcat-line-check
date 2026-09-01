package dev.mikko.tomcatlinecheck;

import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * 命令行入口。
 *
 * <p>回答一个问题:<b>Apache 那句 “upgrade to version 11.0.20, 10.1.52 or 9.0.116” 对你成不成立?</b>
 *
 * <p>对多数人它不成立,而且有四种不同的不成立方式:
 * <ol>
 *   <li>你在 8.5 / 7.0 / 8.0 线上 —— 那三个版本没有一个在你的线上,而你的线已停发;</li>
 *   <li>你在 10.1 线上 —— 它叫你升的 {@code 10.1.52},实测 jar 里没有修复类;</li>
 *   <li>你在 10.0 线上 —— 官方公告压根没提过这条线;</li>
 *   <li>你用 Dependabot / OSV —— 它们会叫 8.5 用户升到 {@code 9.0.116},那是另一条大版本线。</li>
 * </ol>
 */
public final class Main {

    public static void main(String[] args) {
        boolean utf8 = false;
        boolean showTable = false;
        List<String> paths = new ArrayList<>();
        for (String a : args) {
            switch (a) {
                case "--utf8" -> utf8 = true;
                case "--table" -> showTable = true;
                case "-h", "--help" -> {
                    usage(System.out);
                    return;
                }
                default -> paths.add(a);
            }
        }
        // Windows 控制台默认 GBK,中文会花;--utf8 强制按 UTF-8 输出。
        PrintStream out = utf8
                ? new PrintStream(new FileOutputStream(FileDescriptor.out), true, StandardCharsets.UTF_8)
                : System.out;

        if (showTable) {
            printTable(out);
            return;
        }
        if (paths.isEmpty()) {
            usage(out);
            System.exit(2);
            return;
        }

        Scanner sc = new Scanner();
        for (String p : paths) {
            sc.scan(Paths.get(p));
        }
        report(out, sc);
    }

    private static void usage(PrintStream out) {
        out.println("tomcat-line-check - does Apache's upgrade advice for " + LineTable.CVE
                + " actually apply to you?");
        out.println("  (Chinese text garbled? re-run with --utf8)");
        out.println();
        out.println("tomcat-line-check —— " + LineTable.CVE + ":官方叫你升的那一版,对你成不成立");
        out.println();
        out.println("  用法:java -jar tomcat-line-check.jar [选项] <Tomcat 目录 | jar | war> ...");
        out.println();
        out.println("  选项:");
        out.println("    --utf8    按 UTF-8 输出(Windows 控制台中文乱码时用)");
        out.println("    --table   只打印七条大版本线的判定表,不扫描");
        out.println();
        out.println("  判据只有一条,你可以自己复现:");
        out.println("    unzip -l tomcat-coyote-<ver>.jar | grep ChunkExtension");
        out.println("  有这个类 = 带了修复;没有 = 缺修复。**不按版本号比大小** ——");
        out.println("  因为版本号说法本身就是这条 CVE 上出错的地方。");
    }

    private static void printTable(PrintStream out) {
        header(out);
        out.printf("%-6s %-10s %-12s %-10s %-8s %s%n",
                "线", "终版", "EOL", "探测版", "有修复", "出口");
        out.println("-".repeat(72));
        for (LineTable.Line l : LineTable.lines()) {
            out.printf("%-6s %-10s %-12s %-10s %-8s %s%n",
                    l.line(),
                    l.eolLatest(),
                    l.eol() == null ? "(未 EOL)" : l.eol(),
                    l.lastProbed(),
                    l.lastFixed() ? "有" : "无",
                    l.hasExit() ? l.exitVersion()
                            : "❌ 无出口(" + l.nextProbed() + " = 404)");
        }
        out.println();
        out.println("官方 recommend 原文片段:upgrade to version " + LineTable.OFFICIAL_RECOMMEND);
        for (LineTable.Line l : LineTable.lines()) {
            if (Verdict.officialRecommendIsBroken(l)) {
                out.println("🔴 其中 " + l.lastProbed() + " 被列为升级目标,而实测它的 jar 里没有修复类。");
            }
        }
        out.println("🔴 10.0 线不在官方公告的任何一个列表里(受影响、unknown 都没有)。");
    }

    private static void header(PrintStream out) {
        out.println("tomcat-line-check —— " + LineTable.CVE + " (" + LineTable.GHSA + ")");
        out.println("  Apache 原始公告评级:low   ·   GitHub advisory:"
                + LineTable.SEVERITY_GITHUB + " / CVSS " + LineTable.CVSS_GITHUB);
        out.println("  判据:jar 里有没有 " + LineTable.FIX_CLASS);
        out.println();
    }

    private static void report(PrintStream out, Scanner sc) {
        header(out);

        List<Artifact> arts = sc.artifacts();
        if (arts.isEmpty()) {
            out.println("没扫到任何 Tomcat HTTP 构件。");
            out.println("  本工具找的是含 " + LineTable.VULN_CLASS + " 的 jar");
            out.println("  (tomcat-coyote / tomcat-embed-core,以及 war、Spring Boot fat jar 里的同名构件)。");
            printSkipped(out, sc);
            return;
        }

        int missing = 0;
        for (Artifact a : arts) {
            Verdict v = Verdict.of(a);
            if (v.kind() != Verdict.Kind.FIXED) {
                missing++;
            }
            out.println((v.kind() == Verdict.Kind.FIXED ? "✅ " : "🔴 ") + v.headline());
            out.println("   构件:" + a.coordinate());
            out.println("   版本:" + (a.version() == null ? "(读不到)" : a.version())
                    + (a.versionFrom() == null ? "" : "   ← 来自 " + a.versionFrom()));
            out.println("   路径:" + a.source());
            for (String line : v.detail().split("\n")) {
                out.println("   " + line);
            }
            out.println();
        }

        out.println("-".repeat(72));
        out.println("扫到 " + arts.size() + " 个相关构件,其中 " + missing + " 个缺少修复代码。");
        if (missing > 0) {
            out.println();
            out.println("说话的边界(本工具不越过,你也别):");
            out.println("  · 「缺少修复代码」是构件事实;「你受影响」是另一回事,需要上游确认。");
            out.println("  · 请求走私要有前端代理、且两端解读不一致才谈得上危害。");
            out.println("    Apache 自己给这条的评级是 low。别人吓你的时候记得这句。");
        }
        printSkipped(out, sc);
    }

    private static void printSkipped(PrintStream out, Scanner sc) {
        if (sc.skipped().isEmpty()) {
            return;
        }
        out.println();
        out.println("⚠️ 下面这些没扫成 —— 读作「没查到」,不是「没问题」:");
        for (String s : sc.skipped()) {
            out.println("   · " + s);
        }
    }

    private Main() {
    }
}
