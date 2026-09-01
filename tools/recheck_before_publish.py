#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""发文前复核 —— **每一条要对外说的话,都在这里重新跑一遍**。

跑:  python tools/recheck_before_publish.py

═══════════════════════════════════════════════════════════════════════
为什么需要它
═══════════════════════════════════════════════════════════════════════
本注要对外说的话全部建立在**上游此刻的状态**上,而上游会变:

  · Apache 可能更正那句 "upgrade to version ... 10.1.52 ..." —— 一改,主张 ② 就没了。
  · Apache 可能补发 8.5.101 / 7.0.110 —— 一发,主张 ① 就没了。
  · Apache 可能把 10.0 补进公告 —— 一补,主张 ③ 就没了。
  · GitHub 可能调整区间或 first_patched —— 一调,主张 ④ 就没了。

**这四条主张失效时,不会有任何东西报错,文章会安静地变成假话。**
→ 发文当天必须重跑这个脚本;失效了就改文案,别改判据。

☠️ 08-29 第 16 注的教训:复核脚本自己用错口径,**一个坏口径正在替文案背书**。
   所以这里每一条都尽量带阳性对照 —— 判据本身坏了要能看出来。
"""
import json
import re
import sys
import urllib.error
import urllib.request

sys.path.insert(0, __file__.rsplit("\\", 1)[0].rsplit("/", 1)[0])

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from gen_table import CENTRAL, CVE, FIX_CLASS, advisory, probe_jar  # noqa: E402

OK, BAD = "✅", "🔴"
fails = []


def check(name, cond, detail=""):
    print("  %s %s%s" % (OK if cond else BAD, name, ("  —— " + detail) if detail else ""))
    if not cond:
        fails.append(name)


def main():
    print("=" * 72)
    print("发文前复核 —— %s" % CVE)
    print("=" * 72)

    adv = advisory()
    desc = adv["description"]

    print("\n【主张 ②】官方叫 10.1 用户升到 10.1.52,而 10.1.52 自己缺修复")
    rec = adv["recommend_raw"] or ""
    check("官方 recommend 原句里仍写着 10.1.52", "10.1.52" in rec, "原句片段:%r" % rec)
    p1052 = probe_jar("10.1.52")
    p1053 = probe_jar("10.1.53")
    check("10.1.52 的 jar 里仍然没有修复类", p1052["fixed"] is False)
    check("阳性对照:10.1.53 的 jar 里有修复类", p1053["fixed"] is True,
          "对照不过说明判据本身坏了,上面那条不算数")
    check("公告仍把 10.1.52 列为受影响上界",
          re.search(r"10\.1\.0-M1 through 10\.1\.52", desc) is not None)

    print("\n【主张 ①】8.5 / 7.0 / 8.0 没有出口")
    for v in ("8.5.101", "7.0.110", "8.0.54"):
        check("%s 在 Central 上仍是 404" % v, probe_jar(v)["exists"] is False)
    check("阳性对照:8.5.100 仍在 Central 上", probe_jar("8.5.100")["exists"] is True,
          "对照不过说明 404 判据坏了")
    for v in ("8.5", "7.0", "8.0"):
        check("官方 recommend 里仍然没有 %s 线的版本" % v,
              not re.search(r"\b" + v.replace(".", r"\.") + r"\.\d+", rec))

    print("\n【主张 ③】10.0 线被整条漏掉")
    check("官方公告全文里仍然没有 10.0.x", re.search(r"10\.0\.", desc) is None)
    p1002 = probe_jar("10.0.27")
    check("10.0.27 的 jar 里仍然没有修复类", p1002["fixed"] is False)
    check("10.0.28 在 Central 上仍是 404", probe_jar("10.0.28")["exists"] is False)
    covered = any("10.0" in r[1] for r in adv["ranges"])
    check("GitHub advisory 的区间仍然覆盖不到 10.0", not covered,
          "区间:%s" % [r[1] for r in adv["ranges"]])

    print("\n【主张 ④】机器会叫 8.5 用户升到 9.0.116(跨大版本线)")
    hit = [r for r in adv["ranges"] if r[1].startswith(">= 7.0.0")]
    check("仍存在把 7.0/8.5/9.0 压成一条的区间", bool(hit), "区间:%s" % (hit or "无"))
    check("该区间的 first_patched 仍是 9.0.116",
          bool(hit) and hit[0][2] == "9.0.116",
          "实际:%s" % (hit[0][2] if hit else "—"))

    print("\n【主张 ⑤】评级冲突")
    check("GitHub 仍标 high", adv["severity_github"] == "high", adv["severity_github"])
    check("CVSS 仍是 7.5", adv["cvss"] == 7.5, str(adv["cvss"]))
    print("     ⚠️ Apache 原文的 `Severity: low` 只在 oss-security 邮件里,脚本不抓,")
    print("        发文前请人工再看一眼:http://www.openwall.com/lists/oss-security/2026/04/09/20")

    print("\n" + "=" * 72)
    if fails:
        print("🔴 %d 条不过 —— **别发,先改文案**:" % len(fails))
        for f in fails:
            print("   ·", f)
        return 1
    print("✅ 全部通过 —— 文案里的主张此刻仍然成立")
    print("🔴 但仍有两件只能人做:①Apache 原文的 low 评级 ②文案红线逐条扫一遍")
    return 0


if __name__ == "__main__":
    sys.exit(main())
