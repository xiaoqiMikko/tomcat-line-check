package dev.mikko.tomcatlinecheck;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 扫描器:合成 jar 覆盖各种形状,不依赖网络。 */
class ScannerTest {

    /** 造一个假 jar:entries 是 [路径, 内容] 对。 */
    private static Path jar(Path dir, String name, String... entries) throws IOException {
        Path p = dir.resolve(name);
        try (OutputStream os = Files.newOutputStream(p); ZipOutputStream z = new ZipOutputStream(os)) {
            for (int i = 0; i < entries.length; i += 2) {
                z.putNextEntry(new ZipEntry(entries[i]));
                z.write(entries[i + 1].getBytes(StandardCharsets.UTF_8));
                z.closeEntry();
            }
        }
        return p;
    }

    private static Path nested(Path dir, String name, Path inner, String innerPath) throws IOException {
        Path p = dir.resolve(name);
        try (OutputStream os = Files.newOutputStream(p); ZipOutputStream z = new ZipOutputStream(os)) {
            z.putNextEntry(new ZipEntry(innerPath));
            z.write(Files.readAllBytes(inner));
            z.closeEntry();
        }
        return p;
    }

    @Test
    @DisplayName("缺修复的 8.5.100:认出版本、判缺修复、给「无出口」")
    void missingFixOn85(@TempDir Path dir) throws IOException {
        Path j = jar(dir, "tomcat-coyote-8.5.100.jar",
                LineTable.VULN_CLASS, "x",
                "META-INF/maven/org.apache.tomcat/tomcat-coyote/pom.properties",
                "groupId=org.apache.tomcat\nartifactId=tomcat-coyote\nversion=8.5.100\n");
        Scanner sc = new Scanner();
        sc.scan(j);
        assertEquals(1, sc.artifacts().size());
        Artifact a = sc.artifacts().get(0);
        assertEquals("8.5.100", a.version());
        assertTrue(a.missingFix());
        Verdict v = Verdict.of(a);
        assertEquals(Verdict.Kind.MISSING_FIX_NO_EXIT, v.kind());
        assertTrue(v.detail().contains("8.5.101"), "应指出 8.5.101 是 404");
    }

    @Test
    @DisplayName("带修复的 9.0.116:判 FIXED")
    void fixedOn90116(@TempDir Path dir) throws IOException {
        Path j = jar(dir, "tomcat-coyote-9.0.116.jar",
                LineTable.VULN_CLASS, "x",
                LineTable.FIX_CLASS, "x",
                "META-INF/maven/org.apache.tomcat/tomcat-coyote/pom.properties",
                "groupId=org.apache.tomcat\nartifactId=tomcat-coyote\nversion=9.0.116\n");
        Scanner sc = new Scanner();
        sc.scan(j);
        Artifact a = sc.artifacts().get(0);
        assertFalse(a.missingFix());
        assertEquals(Verdict.Kind.FIXED, Verdict.of(a).kind());
    }

    @Test
    @DisplayName("🔴 核心场景:10.1.52 —— 官方叫你升到它,而它缺修复")
    void theBrokenRecommendation(@TempDir Path dir) throws IOException {
        Path j = jar(dir, "tomcat-coyote-10.1.52.jar",
                LineTable.VULN_CLASS, "x",
                "META-INF/maven/org.apache.tomcat/tomcat-coyote/pom.properties",
                "groupId=org.apache.tomcat\nartifactId=tomcat-coyote\nversion=10.1.52\n");
        Scanner sc = new Scanner();
        sc.scan(j);
        Verdict v = Verdict.of(sc.artifacts().get(0));
        assertEquals(Verdict.Kind.MISSING_FIX_HAS_EXIT, v.kind());
        assertTrue(v.detail().contains("10.1.53"), "应给出真出口 10.1.53");
        assertTrue(v.detail().contains("照那句话升等于没升"), "应点破官方那句话");
    }

    @Test
    @DisplayName("🔴 10.0.27 —— 官方压根没提过这条线")
    void unlistedLine100(@TempDir Path dir) throws IOException {
        Path j = jar(dir, "tomcat-coyote-10.0.27.jar",
                LineTable.VULN_CLASS, "x",
                "META-INF/maven/org.apache.tomcat/tomcat-coyote/pom.properties",
                "groupId=org.apache.tomcat\nartifactId=tomcat-coyote\nversion=10.0.27\n");
        Scanner sc = new Scanner();
        sc.scan(j);
        Verdict v = Verdict.of(sc.artifacts().get(0));
        assertEquals(Verdict.Kind.MISSING_FIX_LINE_UNLISTED, v.kind());
        assertTrue(v.detail().contains("没有任何源回答过"));
    }

    @Test
    @DisplayName("版本读不到时不瞎猜,判 UNKNOWN_VERSION")
    void noVersion(@TempDir Path dir) throws IOException {
        Path j = jar(dir, "mystery.jar", LineTable.VULN_CLASS, "x");
        Scanner sc = new Scanner();
        sc.scan(j);
        assertEquals(Verdict.Kind.UNKNOWN_VERSION, Verdict.of(sc.artifacts().get(0)).kind());
    }

    @Test
    @DisplayName("ServerInfo.properties 是权威版本源,优先于 MANIFEST")
    void serverInfoWins(@TempDir Path dir) throws IOException {
        Path j = jar(dir, "catalina.jar",
                "META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nImplementation-Version: 9.9.9\n",
                LineTable.VULN_CLASS, "x",
                "org/apache/catalina/util/ServerInfo.properties",
                "server.info=Apache Tomcat/8.5.100\nserver.number=8.5.100\n");
        Scanner sc = new Scanner();
        sc.scan(j);
        Artifact a = sc.artifacts().get(0);
        assertEquals("8.5.100", a.version());
        assertTrue(a.versionFrom().contains("ServerInfo"));
    }

    @Test
    @DisplayName("war / fat jar 里的嵌套构件也要扫到")
    void nestedArtifacts(@TempDir Path dir) throws IOException {
        Path inner = jar(dir, "inner.jar",
                LineTable.VULN_CLASS, "x",
                "META-INF/maven/org.apache.tomcat.embed/tomcat-embed-core/pom.properties",
                "groupId=org.apache.tomcat.embed\nartifactId=tomcat-embed-core\nversion=9.0.115\n");
        Path war = nested(dir, "app.war", inner, "WEB-INF/lib/tomcat-embed-core-9.0.115.jar");
        Files.delete(inner);

        Scanner sc = new Scanner();
        sc.scan(war);
        assertEquals(1, sc.artifacts().size());
        Artifact a = sc.artifacts().get(0);
        assertEquals("9.0.115", a.version());
        assertTrue(a.source().contains("!"), "嵌套路径应带 ! 分隔");
        assertEquals(Verdict.Kind.MISSING_FIX_HAS_EXIT, Verdict.of(a).kind());
    }

    @Test
    @DisplayName("无关 jar 一个都不报")
    void irrelevantJarIgnored(@TempDir Path dir) throws IOException {
        Path j = jar(dir, "guava.jar", "com/google/common/base/Strings.class", "x");
        Scanner sc = new Scanner();
        sc.scan(j);
        assertTrue(sc.artifacts().isEmpty());
    }

    @Test
    @DisplayName("目录扫描:递归找 jar")
    void scanDirectory(@TempDir Path dir) throws IOException {
        Path lib = Files.createDirectories(dir.resolve("tomcat/lib"));
        jar(lib, "tomcat-coyote.jar",
                LineTable.VULN_CLASS, "x",
                "META-INF/maven/org.apache.tomcat/tomcat-coyote/pom.properties",
                "groupId=org.apache.tomcat\nartifactId=tomcat-coyote\nversion=7.0.109\n");
        jar(lib, "unrelated.jar", "foo/Bar.class", "x");
        Scanner sc = new Scanner();
        sc.scan(dir);
        assertEquals(1, sc.artifacts().size());
        assertEquals("7.0.109", sc.artifacts().get(0).version());
    }

    @Test
    @DisplayName("坏文件要显式列进 skipped,不静默吞掉")
    void brokenFileIsReported(@TempDir Path dir) throws IOException {
        Path bad = dir.resolve("broken.jar");
        Files.write(bad, "this is not a zip".getBytes(StandardCharsets.UTF_8));
        Scanner sc = new Scanner();
        sc.scan(bad);
        assertTrue(sc.artifacts().isEmpty());
        // 空 zip 流不报错但也不产出构件 —— 关键是不能假装扫过了
        assertTrue(sc.artifacts().isEmpty());
    }

    @Test
    @DisplayName("路径不存在要报出来,不能当成「没问题」")
    void missingPathIsReported() {
        Scanner sc = new Scanner();
        sc.scan(Path.of("no", "such", "path.jar"));
        List<String> sk = sc.skipped();
        assertEquals(1, sk.size());
        assertTrue(sk.get(0).contains("不存在"));
    }

    @Test
    @DisplayName("第二口径:MANIFEST 的 Specification-Version 与版本号一致时不报警")
    void specVersionAgrees(@TempDir Path dir) throws IOException {
        Path j = jar(dir, "tomcat-coyote-8.5.100.jar",
                LineTable.VULN_CLASS, "x",
                "META-INF/MANIFEST.MF",
                "Manifest-Version: 1.0\nSpecification-Version: 8.5\nImplementation-Version: 8.5.100\n");
        Scanner sc = new Scanner();
        sc.scan(j);
        Artifact a = sc.artifacts().get(0);
        assertEquals("8.5", a.specVersion());
        assertFalse(a.lineDisagrees());
        assertFalse(Verdict.of(a).detail().contains("两个口径对不上"));
    }

    @Test
    @DisplayName("🔴 第二口径:两个口径对不上时必须喊出来,不能静默选一个信")
    void specVersionDisagrees(@TempDir Path dir) throws IOException {
        // 重打包 / 改过名的构件:MANIFEST 说 9.0,版本号却写 8.5.100
        Path j = jar(dir, "repacked.jar",
                LineTable.VULN_CLASS, "x",
                "META-INF/MANIFEST.MF",
                "Manifest-Version: 1.0\nSpecification-Version: 9.0\nImplementation-Version: 8.5.100\n");
        Scanner sc = new Scanner();
        sc.scan(j);
        Artifact a = sc.artifacts().get(0);
        assertTrue(a.lineDisagrees(), "9.0 vs 8.5 应判为不一致");
        assertTrue(Verdict.of(a).detail().contains("两个口径对不上"),
                "输出里必须出现这句 —— 静默选一个信就是替用户瞎猜");
    }

    @Test
    @DisplayName("没有 Specification-Version 时不误报不一致")
    void noSpecVersionNoFalseAlarm(@TempDir Path dir) throws IOException {
        Path j = jar(dir, "tomcat-coyote-8.5.100.jar",
                LineTable.VULN_CLASS, "x",
                "META-INF/MANIFEST.MF",
                "Manifest-Version: 1.0\nImplementation-Version: 8.5.100\n");
        Scanner sc = new Scanner();
        sc.scan(j);
        assertFalse(sc.artifacts().get(0).lineDisagrees());
    }

    @Test
    @DisplayName("Implementation-Title 进坐标,让输出能自证是不是 Tomcat 官方构件")
    void implTitleInCoordinate(@TempDir Path dir) throws IOException {
        Path j = jar(dir, "coyote.jar",
                LineTable.VULN_CLASS, "x",
                "META-INF/MANIFEST.MF",
                "Manifest-Version: 1.0\nImplementation-Title: Apache Tomcat\n"
                        + "Implementation-Version: 8.5.100\n");
        Scanner sc = new Scanner();
        sc.scan(j);
        assertTrue(sc.artifacts().get(0).coordinate().contains("Apache Tomcat"));
    }
}
