package dev.mikko.tomcatlinecheck;

/**
 * 把一个构件的扫描事实,翻成「官方那句升级建议对你成不成立」。
 *
 * <p>🔴 <b>本类的措辞是有红线的</b>,改之前先看 {@code README.md} 的「说话的边界」一节:
 * <ul>
 *   <li>只说「缺少修复代码」,不说「你受影响」—— 后者要上游确认,而 10.0 线没人确认过;</li>
 *   <li>不谈攻击后果 —— 请求走私要有前端代理才谈得上危害,Apache 自己给的是 {@code low}。</li>
 * </ul>
 */
public final class Verdict {

    /** 判定档位。 */
    public enum Kind {
        /** 构件里有修复类 —— 这一条到此为止。 */
        FIXED,
        /** 缺修复,但你这条线有出口版本可以升。 */
        MISSING_FIX_HAS_EXIT,
        /** 缺修复,而这条线已经停发,没有任何可升的版本。 */
        MISSING_FIX_NO_EXIT,
        /** 缺修复,而官方公告里<b>压根没提过你这条线</b>。 */
        MISSING_FIX_LINE_UNLISTED,
        /** 扫到了构件,但版本号读不出来,给不了线级结论。 */
        UNKNOWN_VERSION
    }

    private final Artifact artifact;
    private final Kind kind;
    private final String headline;
    private final String detail;

    private Verdict(Artifact a, Kind k, String headline, String detail) {
        this.artifact = a;
        this.kind = k;
        this.headline = headline;
        this.detail = detail;
    }

    public Artifact artifact() {
        return artifact;
    }

    public Kind kind() {
        return kind;
    }

    public String headline() {
        return headline;
    }

    public String detail() {
        return detail;
    }

    /**
     * 官方公告 recommend 里列出的版本,本身就缺修复吗。
     *
     * <p>这是本工具最硬的一条,单独判:{@code 10.1.52} 被官方写成升级目标,
     * 而它的 jar 里没有修复类(生成判定表时由 A3 断言守着)。
     */
    public static boolean officialRecommendIsBroken(LineTable.Line line) {
        return line != null
                && LineTable.OFFICIAL_RECOMMEND != null
                && LineTable.OFFICIAL_RECOMMEND.contains(line.lastProbed())
                && !line.lastFixed();
    }

    public static Verdict of(Artifact a) {
        LineTable.Line line = a.line();

        if (a.fixPresent()) {
            return new Verdict(a, Kind.FIXED,
                    "已带修复",
                    "这个构件里有 " + LineTable.FIX_CLASS + " —— " + LineTable.CVE + " 的修复代码在。");
        }
        if (line == null) {
            return new Verdict(a, Kind.UNKNOWN_VERSION,
                    "缺修复,但版本号读不出来",
                    "构件里没有修复类。但没读到版本号,所以给不了「你这条线有没有出口」的结论。"
                            + "把解压后的 Tomcat 目录(含 lib/catalina.jar 的那一级)传进来试试。");
        }

        // 10.0 是特例:它在官方公告和 GitHub 区间里都不存在。
        boolean unlisted = "10.0".equals(line.line());

        StringBuilder d = new StringBuilder();
        d.append("构件里没有 ").append(LineTable.FIX_CLASS).append("。\n");
        if (a.lineDisagrees()) {
            d.append("  ⚠️ 两个口径对不上:MANIFEST 的 Specification-Version 是 ")
                    .append(a.specVersion()).append(",而版本号 ").append(a.version())
                    .append(" 指向 ").append(line.line())
                    .append(" 线。这个 jar 可能被重打包或改过名 —— ")
                    .append("下面按版本号算,但你该自己看一眼。\n");
        }
        d.append("  你这条线:").append(line.line())
                .append("  已知终版 ").append(line.eolLatest())
                .append(line.supported() ? "(仍在支持期" : "(已 EOL")
                .append(line.eol() == null ? "" : ",EOL " + line.eol())
                .append(")\n");

        if (unlisted) {
            d.append("  🔴 官方公告里没有 10.0 这条线 —— 既不在受影响列表,也不在两条 unknown 里。\n")
                    .append("     GitHub advisory 的两个区间也覆盖不到它。\n")
                    .append("     所以:没有任何源回答过「10.0 中没中」,而 ")
                    .append(line.lastProbed()).append(" 的构件里确实没有修复代码,")
                    .append(line.nextProbed()).append(" 在 Maven Central 上是 404。");
            return new Verdict(a, Kind.MISSING_FIX_LINE_UNLISTED,
                    "缺修复,而且官方压根没提过你这条线", d.toString());
        }

        if (line.hasExit()) {
            d.append("  ✅ 出口:升到 ").append(line.exitVersion())
                    .append(" —— 实测该版本的 jar 里有修复类。");
            if (officialRecommendIsBroken(line)) {
                d.append("\n  🔴 注意:官方公告那句 “upgrade to version ")
                        .append(LineTable.OFFICIAL_RECOMMEND).append("” 里写的是 ")
                        .append(line.lastProbed())
                        .append(",而实测 ").append(line.lastProbed())
                        .append(" 的 jar 里没有修复类。照那句话升等于没升。");
            }
            return new Verdict(a, Kind.MISSING_FIX_HAS_EXIT, "缺修复,有出口", d.toString());
        }

        d.append("  ❌ 这条线没有出口:").append(line.nextProbed())
                .append(" 在 Maven Central 上是 404,").append(line.line())
                .append(" 线已停发。\n")
                .append("     官方 recommend 给的是 “").append(LineTable.OFFICIAL_RECOMMEND)
                .append("” —— 没有一个在 ").append(line.line()).append(" 线上。");
        return new Verdict(a, Kind.MISSING_FIX_NO_EXIT, "缺修复,而且这条线没有出口", d.toString());
    }
}
