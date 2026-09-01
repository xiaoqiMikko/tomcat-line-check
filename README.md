# tomcat-line-check

**CVE-2026-24880 · GHSA-563x-q5rq-57qp** —— Apache 那句
`upgrade to version 11.0.20, 10.1.52 or 9.0.116` 对你成不成立?

对多数人不成立,而且有四种不同的不成立方式。这个工具扫你的构件,告诉你是哪一种。

```
java -jar tomcat-line-check.jar /path/to/tomcat        # 解压部署的 Tomcat
java -jar tomcat-line-check.jar app.war                # war
java -jar tomcat-line-check.jar app.jar                # Spring Boot fat jar
java -jar tomcat-line-check.jar --table                # 只看七条线的判定表
java -jar tomcat-line-check.jar --utf8 ...             # Windows 控制台中文乱码时加
```

## 判据只有一条,你可以自己复现

```bash
unzip -l tomcat-coyote-<ver>.jar | grep ChunkExtension
```

有 `org/apache/tomcat/util/http/parser/ChunkExtension.class` = 带了修复;没有 = 缺修复。

🔴 **本工具不按版本号比大小判修没修** —— 因为版本号说法本身就是这条 CVE 上出错的地方。
判定表由 `tools/gen_table.py` 从一手源生成,七组断言不过就拒绝出表。

## 七条线的实测结果

| 线 | 终版 | EOL | 有修复 | 出口 |
|---|---|---|---|---|
| 7.0 | 7.0.109 | 2021-03-31 | 无 | ❌ `7.0.110` = 404 |
| 8.0 | 8.0.53 | 2018-06-30 | 无 | ❌ `8.0.54` = 404 |
| 8.5 | 8.5.100 | 2024-03-31 | 无 | ❌ `8.5.101` = 404 |
| **10.0** | 10.0.27 | 2022-10-31 | 无 | ❌ `10.0.28` = 404 |
| 9.0 | 9.0.121 | 2027-03-31 | 9.0.115 无 | ✅ **9.0.116** |
| 10.1 | 10.1.59 | 未 EOL | **10.1.52 无** | ✅ **10.1.53** |
| 11.0 | 11.0.25 | 未 EOL | 11.0.18 无 | ✅ **11.0.20** |

### 四种「官方那句话对你不成立」

**① 你在 8.5 / 7.0 / 8.0 线上** —— 官方给的三个版本没有一个在你的线上,
而你的线已停发(`8.5.101` / `7.0.110` / `8.0.54` 在 Maven Central 上都是 404)。
8.0 更特别:官方把它标成 `unknown`,连「你中没中」都没回答。

**② 你在 10.1 线上 —— 官方叫你升到 `10.1.52`,而 `10.1.52` 自己就缺修复。**
同一封公告的上一段把 `10.1.0-M1 through 10.1.52` 列为受影响。
Apache 自己的 [security-10.html](https://tomcat.apache.org/security-10.html)
把这条 CVE 归在 **10.1.53** 小节;`compare 10.1.52...10.1.53` 里也确实包含修复 commit `f07df938`。
→ **照那句话升等于没升。**

**③ 你在 10.0 线上 —— 官方公告里 `10.0.` 出现 0 次。**
既不在受影响列表,也不在两条 `unknown` 里;GitHub advisory 的两个区间
(`>= 7.0.0, < 9.0.116` 和 `>= 10.1.0-M1, < 10.1.52`)也都覆盖不到它。
而 `10.0.27` 的 `ChunkedInputFilter` 成员与 `7.0.109` / `8.5.100` 逐字相同,`10.0.28` 是 404。
→ **没有任何源回答过 10.0 中没中。**

**④ 你用 Dependabot / OSV** —— GitHub advisory 把 7.0/8.5/9.0 压成一个区间,
`first_patched_version = 9.0.116`,于是机器会叫 8.5 用户升到 **9.0.116**。
那是另一条大版本线,不是打补丁。

## 说话的边界(本工具不越过,你也别)

- **「缺少修复代码」是构件事实;「你受影响」是另一回事**,需要上游确认 ——
  而 10.0 线恰恰没人确认过。本工具的措辞一律是前者。
- **请求走私要有前端代理、且两端解读不一致才谈得上危害。** 裸跑的 Tomcat 上讲不出攻击故事。
- **Apache 原始公告给这条的评级是 `low`**(GitHub advisory 标 `high` / CVSS 7.5)。
  两个数都列在这里,不挑对自己有利的那个说。

## 一手源

- Apache 原始公告(oss-security,Mark Thomas,2026-04-09):
  <http://www.openwall.com/lists/oss-security/2026/04/09/20>
- GitHub advisory:<https://github.com/advisories/GHSA-563x-q5rq-57qp>
- 修复 commit:`1b586d6`(9.0)· `f07df938`(10.1)· `fde1a82`(11.0)
- 版本线与 EOL:<https://endoflife.date/tomcat>

## 重新生成判定表

```bash
python tools/gen_table.py --dry     # 只跑断言,不写文件
python tools/gen_table.py           # 断言全过才写 LineTable.java
```

断言涵盖:阳性(9.0.116 / 10.1.53 / 11.0.20 必须有修复类)、阴性(9.0.115 / 10.1.52 必须没有)、
核心主张(官方 recommend 里写的正是 10.1.52)、EOL 线、无出口(终版下一版必须 404)、
哨兵(一个不存在的版本必须 404,证明 404 判据本身没坏)、10.0 缺席。

## 构建

```bash
mvn package      # 需要 JDK 17;运行时零依赖
```

## License

Apache-2.0
