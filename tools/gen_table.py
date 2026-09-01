#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""从一手源生成 LineTable.java —— **判定表不手抄**。

跑:  python tools/gen_table.py            # 生成 + 全部断言
     python tools/gen_table.py --dry      # 只打印,不写文件

═══════════════════════════════════════════════════════════════════════
🔴 为什么判据是「jar 里有没有 ChunkExtension.class」,而不是版本号比大小
═══════════════════════════════════════════════════════════════════════
因为**本工具要打的就是「版本号说法不可信」**:

  · 官方公告叫 10.1 用户升到 `10.1.52`,而 10.1.52 的 jar 里没有修复类。
  · GitHub advisory 把 7.0/8.5/9.0 压成一个区间,`first_patched = 9.0.116`,
    于是机器会叫 8.5 用户升到另一条大版本线。
  · 10.0 线在两个源里都不存在,而它的 jar 同样缺修复。

**如果本工具也用版本号比大小,它就会复读同一批错误说法。**
→ 判据只有一条,且任何人都能用一条命令复现:

    unzip -l tomcat-coyote-<ver>.jar | grep ChunkExtension

═══════════════════════════════════════════════════════════════════════
🔬 断言(不过就拒绝出表 —— 抄 spring-cvss-check/tools/gen_rules.py 的做法)
═══════════════════════════════════════════════════════════════════════
  A1 阳性:9.0.116 / 10.1.53 / 11.0.20 **必须**有 ChunkExtension.class
  A2 阴性:9.0.115 / 10.1.52 **必须**没有
  A3 核心主张:10.1.52 没有,而官方公告 recommend 里写的正是 10.1.52
  A4 EOL 线:7.0.109 / 8.0.53 / 8.5.100 / 10.0.27 都没有修复类
  A5 无出口:7.0.110 / 8.0.54 / 8.5.101 / 10.0.28 在 Central 上必须 404
  A6 哨兵:一个不存在的版本必须 404(证明 404 判据本身没坏)

☠️ A6 是踩过的坑的产物:**没有哨兵,「全都 404」和「网络坏了」长得一模一样。**
"""
import argparse
import io
import json
import re
import sys
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

UA = {"User-Agent": "tomcat-line-check/0.1 (+https://github.com/xiaoqiMikko/tomcat-line-check)"}
CENTRAL = "https://repo1.maven.org/maven2/org/apache/tomcat/tomcat-coyote/{v}/tomcat-coyote-{v}.jar"
FIX_CLASS = "org/apache/tomcat/util/http/parser/ChunkExtension.class"
VULN_CLASS = "org/apache/coyote/http11/filters/ChunkedInputFilter.class"
CVE = "CVE-2026-24880"

# 六条线的「终版 + 终版下一版」。终版取自 endoflife.date,下一版是终版号 +1(用来证明「无处可升」)。
# 🔴 这里只写**要探测哪些版本**,探测结果一律来自网络,不写死。
PROBE = {
    "7.0":  ("7.0.109", "7.0.110"),
    "8.0":  ("8.0.53",  "8.0.54"),
    "8.5":  ("8.5.100", "8.5.101"),
    "10.0": ("10.0.27", "10.0.28"),
    "9.0":  ("9.0.115", "9.0.116"),
    "10.1": ("10.1.52", "10.1.53"),
    "11.0": ("11.0.18", "11.0.20"),
}
SENTINEL = "9.9.999"          # A6 哨兵:必须 404


def get(url, timeout=60):
    req = urllib.request.Request(url, headers=UA)
    return urllib.request.urlopen(req, timeout=timeout)


def probe_jar(ver):
    """下载真 jar,回答三件事:在不在 Central、有没有修复类、有没有受影响类。"""
    try:
        raw = get(CENTRAL.format(v=ver)).read()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"exists": False, "fixed": None, "hasFilter": None}
        raise
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        names = set(z.namelist())
    return {"exists": True, "fixed": FIX_CLASS in names, "hasFilter": VULN_CLASS in names}


def eol_data():
    d = json.load(get("https://endoflife.date/api/tomcat.json"))
    out = {}
    for c in d:
        cycle = str(c.get("cycle"))
        cycle = "7.0" if cycle == "7" else cycle
        # endoflife.date 用 False 表示「没有 EOL 日期」,用字符串表示有。
        # 🔴 False 不能直接往下传:它会被渲染成字符串 "False",而那是个假日期。
        e = c.get("eol")
        out[cycle] = {"eol": (e if isinstance(e, str) else None), "latest": c.get("latest")}
    return out


def advisory():
    """官方 recommend 的版本 + GitHub advisory 的区间/first_patched。"""
    d = json.load(get("https://api.github.com/advisories?cve_id=" + CVE))
    a = d[0]
    # ☠️ 别用 [^.]+ —— 版本号里全是点,那样必然匹配失败,而失败是静默的(rec=None)。
    # 这个 bug 09-01 被 A3 断言当场抓住,是「断言不过就拒绝出表」第一次真的救场。
    rec = re.search(r"upgrade to version (.+?),?\s*which fix", a["description"])
    ranges = [(v["package"]["name"], v["vulnerable_version_range"], v["first_patched_version"])
              for v in a["vulnerabilities"]]
    return {
        "ghsa": a["ghsa_id"],
        "severity_github": a["severity"],
        "cvss": (a.get("cvss_severities") or {}).get("cvss_v3", {}).get("score"),
        "recommend_raw": rec.group(1).strip() if rec else None,
        "description": a["description"],
        "ranges": ranges,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry", action="store_true")
    args = ap.parse_args()

    print("拉一手源 …")
    adv = advisory()
    eol = eol_data()
    print("  advisory %s  severity(GitHub)=%s  cvss=%s"
          % (adv["ghsa"], adv["severity_github"], adv["cvss"]))
    print("  官方 recommend 原句片段:%r" % (adv["recommend_raw"],))

    rows = {}
    for line, (last, nxt) in PROBE.items():
        rows[line] = {
            "line": line,
            "lastProbed": last, "last": probe_jar(last),
            "nextProbed": nxt, "next": probe_jar(nxt),
            "eol": eol.get(line, {}).get("eol"),
            "eolLatest": eol.get(line, {}).get("latest"),
        }
        r = rows[line]
        print("  %5s  %s exists=%s fixed=%s   |  %s exists=%s fixed=%s   eol=%s latest=%s"
              % (line, last, r["last"]["exists"], r["last"]["fixed"],
                 nxt, r["next"]["exists"], r["next"]["fixed"], r["eol"], r["eolLatest"]))
    sent = probe_jar(SENTINEL)

    # ── 断言 ────────────────────────────────────────────────────────────
    errs = []

    def need(cond, msg):
        if not cond:
            errs.append(msg)

    need(rows["9.0"]["next"]["fixed"] is True, "A1 9.0.116 应有 ChunkExtension.class")
    need(rows["10.1"]["next"]["fixed"] is True, "A1 10.1.53 应有 ChunkExtension.class")
    need(rows["11.0"]["next"]["fixed"] is True, "A1 11.0.20 应有 ChunkExtension.class")
    need(rows["9.0"]["last"]["fixed"] is False, "A2 9.0.115 不该有 ChunkExtension.class")
    need(rows["10.1"]["last"]["fixed"] is False, "A2 10.1.52 不该有 ChunkExtension.class")
    need("10.1.52" in (adv["recommend_raw"] or ""),
         "A3 官方 recommend 里没有 10.1.52 —— 上游可能已更正,核心主张要重写")
    need(rows["10.1"]["last"]["fixed"] is False and "10.1.52" in (adv["recommend_raw"] or ""),
         "A3 核心主张(官方叫你升到一个没修的版本)不成立了")
    for ln in ("7.0", "8.0", "8.5", "10.0"):
        need(rows[ln]["last"]["fixed"] is False, "A4 %s 不该有修复类" % rows[ln]["lastProbed"])
        need(rows[ln]["next"]["exists"] is False, "A5 %s 应该 404(无处可升)" % rows[ln]["nextProbed"])
    need(sent["exists"] is False, "A6 哨兵版本竟然存在 —— 404 判据本身坏了")
    need(any(r["last"]["exists"] for r in rows.values()), "A6 一个 jar 都没下到 —— 网络或 Central 坏了")
    need(re.search(r"10\.0\.", adv["description"]) is None,
         "A7 官方描述里出现了 10.0 —— 「10.0 被漏掉」这条主张要重写")

    if errs:
        print("\n🔴 断言不过,拒绝出表:")
        for e in errs:
            print("   ·", e)
        return 1
    print("\n✅ 断言全过(A1 阳性 / A2 阴性 / A3 核心主张 / A4 EOL 线 / A5 无出口 / A6 哨兵 / A7 10.0 缺席)")

    if args.dry:
        return 0

    out = Path(__file__).resolve().parents[1] / "src/main/java/dev/mikko/tomcatlinecheck/LineTable.java"
    out.write_text(render(rows, adv), encoding="utf-8")
    print("✅ 已写 %s" % out)
    return 0


def j(s):
    if s is None:
        return "null"
    return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"') + '"'


def render(rows, adv):
    order = ["7.0", "8.0", "8.5", "9.0", "10.0", "10.1", "11.0"]
    body = []
    for ln in order:
        r = rows[ln]
        # 这条线有没有出口 = 终版的下一版存在 且 它带修复类
        exit_ver = r["nextProbed"] if (r["next"]["exists"] and r["next"]["fixed"]) else None
        body.append(
            "            new Line(%s, %s, %s, %s, %s, %s, %s, %s)"
            % (j(ln), j(r["eolLatest"]), j(r["eol"]),
               j(r["lastProbed"]), str(bool(r["last"]["fixed"])).lower(),
               j(r["nextProbed"]), str(r["next"]["exists"]).lower(), j(exit_ver))
        )
    lines_src = ",\n".join(body)
    return TEMPLATE % {
        "cve": CVE,
        "ghsa": adv["ghsa"],
        "severity": adv["severity_github"],
        "cvss": adv["cvss"],
        "recommend": j(adv["recommend_raw"]),
        "fix_class": FIX_CLASS,
        "vuln_class": VULN_CLASS,
        "lines": lines_src,
    }


TEMPLATE = '''package dev.mikko.tomcatlinecheck;

import java.util.List;

/**
 * 🔴 本文件由 {@code tools/gen_table.py} 从一手源生成 —— <b>不要手改</b>。
 * 改了下次生成会被覆盖,而且手抄正是这个项目要打的那个错。
 *
 * <p>一手源:GitHub advisory %(ghsa)s · endoflife.date · Maven Central 真 jar 探测。
 * 生成时七组断言全过(阳性 / 阴性 / 核心主张 / EOL 线 / 无出口 / 哨兵 / 10.0 缺席)。
 */
public final class LineTable {

    /** 本工具针对的那一条 CVE。 */
    public static final String CVE = "%(cve)s";
    /** GitHub advisory 编号。 */
    public static final String GHSA = "%(ghsa)s";
    /** GitHub 给的等级 —— 与 Apache 原文的 {@code low} 不同,见 README。 */
    public static final String SEVERITY_GITHUB = "%(severity)s";
    /** GitHub 给的 CVSS v3 分数。 */
    public static final double CVSS_GITHUB = %(cvss)s;
    /** Apache 原始公告里那句 recommend 的原文片段。 */
    public static final String OFFICIAL_RECOMMEND = %(recommend)s;

    /** 修复类:存在 = 这个构件带了修复。这是本工具唯一的硬判据。 */
    public static final String FIX_CLASS = "%(fix_class)s";
    /** 受影响类:存在 = 这个构件里确实有那段代码(用来区分「没修」和「根本不是 coyote」)。 */
    public static final String VULN_CLASS = "%(vuln_class)s";

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
%(lines)s
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
'''


if __name__ == "__main__":
    sys.exit(main())
