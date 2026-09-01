package dev.mikko.tomcatlinecheck;

import java.util.List;

/**
 * 🔴 本文件由 {@code tools/gen_table.py} 从一手源生成 —— <b>不要手改</b>。
 * 改了下次生成会被覆盖,而且手抄正是这个项目要打的那个错。
 *
 * <p>一手源:GitHub advisory GHSA-563x-q5rq-57qp · endoflife.date · Maven Central 真 jar 探测。
 * 生成时七组断言全过(阳性 / 阴性 / 核心主张 / EOL 线 / 无出口 / 哨兵 / 10.0 缺席)。
 */
public final class LineTable {

    /** 本工具针对的那一条 CVE。 */
    public static final String CVE = "CVE-2026-24880";
    /** GitHub advisory 编号。 */
    public static final String GHSA = "GHSA-563x-q5rq-57qp";
    /** GitHub 给的等级 —— 与 Apache 原文的 {@code low} 不同,见 README。 */
    public static final String SEVERITY_GITHUB = "high";
    /** GitHub 给的 CVSS v3 分数。 */
    public static final double CVSS_GITHUB = 7.5;
    /** Apache 原始公告里那句 recommend 的原文片段。 */
    public static final String OFFICIAL_RECOMMEND = "11.0.20, 10.1.52 or 9.0.116";

    /** 修复类:存在 = 这个构件带了修复。这是本工具唯一的硬判据。 */
    public static final String FIX_CLASS = "org/apache/tomcat/util/http/parser/ChunkExtension.class";
    /** 受影响类:存在 = 这个构件里确实有那段代码(用来区分「没修」和「根本不是 coyote」)。 */
    public static final String VULN_CLASS = "org/apache/coyote/http11/filters/ChunkedInputFilter.class";

    /**
     * 一条大版本线。
     *
     * @param line        线名,如 {@code 8.5}
     * @param eolLatest   endoflife.date 记的该线最新版
     * @param eol         EOL 日期;{@code null} 表示该线仍在支持期
     * @param lastProbed  实际探测过的终版
     * @param lastFixed   终版的 jar 里有没有修复类
     * @param nextProbed  终版的下一版号(用来证明「无处可升」)
     * @param nextExists  下一版在 Central 上存不存在
     * @param exitVersion 这条线的出口版本;{@code null} = <b>没有出口</b>
     */
    public record Line(String line, String eolLatest, String eol,
                       String lastProbed, boolean lastFixed,
                       String nextProbed, boolean nextExists,
                       String exitVersion) {

        /** 这条线有没有可升的、带修复的版本。 */
        public boolean hasExit() {
            return exitVersion != null;
        }

        /**
         * 这条线还在支持期吗 —— <b>运行期算,不烤进表里</b>。
         *
         * <p>9.0 线的 EOL 是 2027-03-31:它有日期,但那个日期在未来。
         * 如果按「eol 是不是 null」判,9.0 会被错判成已 EOL。
         */
        public boolean supported() {
            if (eol == null) {
                return true;
            }
            try {
                return java.time.LocalDate.parse(eol).isAfter(java.time.LocalDate.now());
            } catch (java.time.format.DateTimeParseException e) {
                return false;
            }
        }
    }

    private static final List<Line> LINES = List.of(
            new Line("7.0", "7.0.109", "2021-03-31", "7.0.109", false, "7.0.110", false, null),
            new Line("8.0", "8.0.53", "2018-06-30", "8.0.53", false, "8.0.54", false, null),
            new Line("8.5", "8.5.100", "2024-03-31", "8.5.100", false, "8.5.101", false, null),
            new Line("9.0", "9.0.121", "2027-03-31", "9.0.115", false, "9.0.116", true, "9.0.116"),
            new Line("10.0", "10.0.27", "2022-10-31", "10.0.27", false, "10.0.28", false, null),
            new Line("10.1", "10.1.59", null, "10.1.52", false, "10.1.53", true, "10.1.53"),
            new Line("11.0", "11.0.25", null, "11.0.18", false, "11.0.20", true, "11.0.20")
    );

    public static List<Line> lines() {
        return LINES;
    }

    /** 按版本号找它属于哪条线;找不到返回 {@code null}。 */
    public static Line lineOf(String version) {
        if (version == null) {
            return null;
        }
        Line best = null;
        for (Line l : LINES) {
            if (version.equals(l.line()) || version.startsWith(l.line() + ".")) {
                if (best == null || l.line().length() > best.line().length()) {
                    best = l;
                }
            }
        }
        return best;
    }

    private LineTable() {
    }
}
