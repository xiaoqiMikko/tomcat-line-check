package dev.mikko.tomcatlinecheck;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * 扫描器:从目录 / jar / war / Spring Boot fat jar 里找出 Tomcat 构件。
 *
 * <p>判据只有一条,且任何人都能用一条命令复现:
 * <pre>unzip -l tomcat-coyote-&lt;ver&gt;.jar | grep ChunkExtension</pre>
 *
 * <p>🔴 <b>不按版本号比大小判修没修</b> —— 那正是本工具要打的那个错。
 * 版本号只用来回答「你这条线有没有出口」,判「你手上这个构件修没修」一律看类。
 */
public final class Scanner {

    /** 嵌套解压的深度上限。war 里套 jar 是常见的,再深就不正常了,防 zip bomb。 */
    private static final int MAX_DEPTH = 3;

    private final List<Artifact> found = new ArrayList<>();
    private final List<String> skipped = new ArrayList<>();

    public List<Artifact> artifacts() {
        return found;
    }

    /** 扫不动的东西(坏 zip、读不了的文件)—— <b>显式列出来,不静默吞掉</b>。 */
    public List<String> skipped() {
        return skipped;
    }

    public void scan(Path p) {
        if (!Files.exists(p)) {
            skipped.add(p + " —— 路径不存在");
            return;
        }
        if (Files.isDirectory(p)) {
            scanDir(p);
        } else {
            scanArchive(p.toString(), readAll(p), 0);
        }
    }

    private void scanDir(Path dir) {
        try (var s = Files.walk(dir)) {
            s.filter(Files::isRegularFile)
                    .filter(f -> {
                        String n = f.getFileName().toString().toLowerCase(Locale.ROOT);
                        return n.endsWith(".jar") || n.endsWith(".war");
                    })
                    .forEach(f -> scanArchive(f.toString(), readAll(f), 0));
        } catch (IOException e) {
            skipped.add(dir + " —— 目录遍历失败:" + e.getMessage());
        }
    }

    private byte[] readAll(Path p) {
        try {
            return Files.readAllBytes(p);
        } catch (IOException e) {
            skipped.add(p + " —— 读不了:" + e.getMessage());
            return null;
        }
    }

    /**
     * ☠️ <b>ZipInputStream 对非 zip 内容不抛异常,只是一个条目都不给</b>(2026-09-08 实测)。
     *
     * <p>后果:损坏 / 加密 / 根本不是 zip 的 .jar 会静默走完扫描,得出「没扫到 Tomcat」——
     * 用户会把它读成「我不受影响」。<b>「读不动」和「你是安全的」必须是两句话。</b>
     *
     * <p>🔴 第 10 注(log4j-check)实测记过并在那一注加了防线,但后续各注的扫描代码是复制来的,
     * <b>防线没跟着传下来</b>。空 zip({@code PK\05\06})合法,不算坏文件。
     */
    static boolean looksLikeZip(byte[] b) {
        if (b == null || b.length < 4 || b[0] != 'P' || b[1] != 'K') return false;
        int c = b[2], d = b[3];
        return (c == 3 && d == 4) || (c == 5 && d == 6) || (c == 7 && d == 8);
    }


    /**
     * 是不是一个<b>合法的空 zip</b> —— 整个文件就是一条 22 字节的 EOCD 记录。
     *
     * <p>🔴 判据不是「魔数像 zip」:一个 PK 03 04 开头但截断的文件魔数也是对的。
     * 空 zip 是真的空,不该报错;截断的必须报。
     */
    static boolean isEmptyZip(byte[] b) {
        return b != null && b.length == 22
                && b[0] == 'P' && b[1] == 'K' && b[2] == 5 && b[3] == 6;
    }

    private void scanArchive(String source, byte[] bytes, int depth) {
        if (bytes == null || depth > MAX_DEPTH) {
            return;
        }
        if (!looksLikeZip(bytes)) {
            skipped.add(source + " —— 读不动,不是有效的 zip/jar(截断、加密,或其实是个 HTML 错误页)"
                    + " —— 🔴 这不等于「里面没有 Tomcat」");
            return;
        }
        boolean fix = false;
        boolean vuln = false;
        String version = null;
        String versionFrom = null;
        String coordinate = null;
        String specVersion = null;
        String implTitle = null;
        List<String[]> nested = new ArrayList<>();
        List<byte[]> nestedBytes = new ArrayList<>();

        int entries = 0;
        try (ZipInputStream zin = new ZipInputStream(new ByteArrayInputStream(bytes))) {
            ZipEntry e;
            while ((e = zin.getNextEntry()) != null) {
                entries++;
                String name = e.getName();
                if (LineTable.FIX_CLASS.equals(name)) {
                    fix = true;
                } else if (LineTable.VULN_CLASS.equals(name)) {
                    vuln = true;
                } else if (name.startsWith("META-INF/maven/org.apache.tomcat")
                        && name.endsWith("/pom.properties")) {
                    Properties pr = new Properties();
                    pr.load(new ByteArrayInputStream(drain(zin)));
                    if (pr.getProperty("version") != null) {
                        version = pr.getProperty("version");
                        versionFrom = "pom.properties";
                        coordinate = pr.getProperty("groupId") + ":" + pr.getProperty("artifactId");
                    }
                } else if ("META-INF/MANIFEST.MF".equals(name)) {
                    String mf = new String(drain(zin), StandardCharsets.UTF_8);
                    // Tomcat 的 jar 是 Ant 打的,没有 pom.properties,MANIFEST 才是唯一的源。
                    specVersion = manifestValue(mf, "Specification-Version");
                    implTitle = manifestValue(mf, "Implementation-Title");
                    String v = manifestValue(mf, "Implementation-Version");
                    if (v != null && version == null) {
                        version = v;
                        versionFrom = "MANIFEST.MF";
                    }
                } else if (name.endsWith("org/apache/catalina/util/ServerInfo.properties")) {
                    // 解压部署的 Tomcat:catalina.jar 里这个文件才是权威版本号。
                    Properties pr = new Properties();
                    pr.load(new ByteArrayInputStream(drain(zin)));
                    String v = pr.getProperty("server.number");
                    if (v != null) {
                        version = v;
                        versionFrom = "ServerInfo.properties(权威)";
                    }
                } else if (depth < MAX_DEPTH
                        && (name.endsWith(".jar") || name.endsWith(".war"))
                        && !e.isDirectory()) {
                    // war 的 WEB-INF/lib、Spring Boot fat jar 的 BOOT-INF/lib
                    nested.add(new String[]{source + "!" + name});
                    nestedBytes.add(drain(zin));
                }
            }
        } catch (IOException ex) {
            skipped.add(source + " —— 不是可读的 zip:" + ex.getMessage());
            return;
        }

        // 🔴 第二层防线:魔数对、也没抛异常,但一个条目都没解出来。
        //    ☠️ 2026-09-08 实测:魔数校验只挡住一半 —— PK 03 04 开头但**内容截断**的文件
        //    魔数是对的、ZipInputStream 也不抛异常,只是零条目。少了这一层它照样静默通过。
        if (entries == 0 && !isEmptyZip(bytes)) {
            skipped.add(source + " —— 魔数像 zip,但一个条目都解不出来(多半是截断或下载不全)"
                    + " —— 🔴 这不等于「里面没有 Tomcat」");
            return;
        }

        if (fix || vuln) {
            String coord = coordinate;
            if (coord == null) {
                coord = implTitle != null
                        ? implTitle + " / " + guessCoordinate(source)
                        : guessCoordinate(source);
            }
            found.add(new Artifact(source, coord, version, versionFrom, specVersion, fix, vuln));
        }
        for (int i = 0; i < nested.size(); i++) {
            scanArchive(nested.get(i)[0], nestedBytes.get(i), depth + 1);
        }
    }

    private static byte[] drain(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) {
            bos.write(buf, 0, n);
        }
        return bos.toByteArray();
    }

    private static String manifestValue(String mf, String key) {
        for (String line : mf.split("\r?\n")) {
            if (line.startsWith(key + ":")) {
                String v = line.substring(key.length() + 1).trim();
                return v.isEmpty() ? null : v;
            }
        }
        return null;
    }

    /** 连 pom.properties 都没有时,退回按文件名猜坐标 —— 并且<b>说清楚这是猜的</b>。 */
    private static String guessCoordinate(String source) {
        String n = source.substring(source.replace('\\', '/').lastIndexOf('/') + 1);
        if (n.contains("embed-core")) {
            return "org.apache.tomcat.embed:tomcat-embed-core(按文件名推断)";
        }
        if (n.contains("coyote")) {
            return "org.apache.tomcat:tomcat-coyote(按文件名推断)";
        }
        return n + "(坐标未知)";
    }
}
