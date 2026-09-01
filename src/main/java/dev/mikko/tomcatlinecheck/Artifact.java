package dev.mikko.tomcatlinecheck;

/**
 * 一个被扫到的 Tomcat 构件,以及对它的<b>构件级</b>判定。
 *
 * <p>🔴 注意 {@link #fixPresent()} 与 {@link #version()} 是<b>两个独立的事实</b>,
 * 本工具的全部价值就建立在「它们可能对不上」这件事上:
 * {@code 10.1.52} 这个版本号被官方公告写成升级目标,而它的 jar 里没有修复类。
 *
 * @param source      这个构件是从哪儿扫出来的(文件路径,嵌套的话带 {@code !} 分隔)
 * @param coordinate  构件坐标,如 {@code org.apache.tomcat:tomcat-coyote}
 * @param version     读到的版本号;读不到是 {@code null}
 * @param versionFrom 版本号是从哪儿读的(用来让人判断这个版本号可不可信)
 * @param specVersion MANIFEST 的 {@code Specification-Version},Tomcat 把大版本线写在这里
 *                    (如 {@code 8.5})—— <b>独立于 Implementation-Version 的第二个口径</b>
 * @param fixPresent  jar 里有没有 {@link LineTable#FIX_CLASS}
 * @param vulnPresent jar 里有没有 {@link LineTable#VULN_CLASS}
 */
public record Artifact(String source, String coordinate, String version,
                       String versionFrom, String specVersion,
                       boolean fixPresent, boolean vulnPresent) {

    /** 这个构件跟本 CVE 有没有关系 —— 没有那两个类之一就是无关构件。 */
    public boolean relevant() {
        return fixPresent || vulnPresent;
    }

    /**
     * 构件级判定:<b>缺少修复代码</b>。
     *
     * <p>🔴 措辞是「缺少修复代码」,不是「受影响」——
     * 「受影响」是个需要上游确认的结论,而 10.0 线恰恰没人确认过。
     */
    public boolean missingFix() {
        return vulnPresent && !fixPresent;
    }

    /**
     * 两个口径对不上吗 —— MANIFEST 说的线,和从版本号推出来的线。
     *
     * <p>🔴 对不上不代表谁错,但<b>必须说出来</b>:jar 被改过名、版本号被人手改过、
     * 或者这根本是个重打包的构件,都会落在这里。静默选一个信,就是在替用户瞎猜。
     */
    public boolean lineDisagrees() {
        LineTable.Line l = line();
        return specVersion != null && l != null && !specVersion.equals(l.line());
    }

    /** 它属于哪条大版本线;版本号读不到或不认识时返回 {@code null}。 */
    public LineTable.Line line() {
        return LineTable.lineOf(version);
    }
}
