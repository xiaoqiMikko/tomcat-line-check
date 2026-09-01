package dev.mikko.tomcatlinecheck;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 判定表的回归锚点。
 *
 * <p>🔴 这些不是「测代码写没写对」,是<b>钉住本注的核心主张</b> ——
 * 哪天上游改了、生成器重跑出不同的表,这里必须红,而不是安静地把文案变成假话。
 */
class LineTableTest {

    @Test
    @DisplayName("核心主张:官方 recommend 里的 10.1.52,自己就缺修复")
    void officialRecommendIsBroken() {
        LineTable.Line l101 = LineTable.lineOf("10.1.52");
        assertNotNull(l101);
        assertEquals("10.1", l101.line());
        assertTrue(LineTable.OFFICIAL_RECOMMEND.contains("10.1.52"),
                "官方 recommend 原句里应含 10.1.52 —— 不含说明上游改了,文案要重写");
        assertFalse(l101.lastFixed(), "10.1.52 的 jar 里不该有修复类");
        assertTrue(Verdict.officialRecommendIsBroken(l101));
    }

    @Test
    @DisplayName("10.1 线的真出口是 10.1.53,不是官方说的 10.1.52")
    void realExitIs1053() {
        assertEquals("10.1.53", LineTable.lineOf("10.1.52").exitVersion());
    }

    @Test
    @DisplayName("三条 EOL 线没有出口:7.0 / 8.0 / 8.5")
    void eolLinesHaveNoExit() {
        for (String v : new String[]{"7.0.109", "8.0.53", "8.5.100"}) {
            LineTable.Line l = LineTable.lineOf(v);
            assertNotNull(l, v + " 应该能定位到线");
            assertFalse(l.hasExit(), v + " 那条线不该有出口");
            assertNull(l.exitVersion());
            assertFalse(l.lastFixed(), v + " 不该带修复类");
        }
    }

    @Test
    @DisplayName("10.0 线同样没出口 —— 而它还不在官方任何列表里")
    void line100HasNoExit() {
        LineTable.Line l = LineTable.lineOf("10.0.27");
        assertNotNull(l);
        assertEquals("10.0", l.line());
        assertFalse(l.hasExit());
        assertFalse(LineTable.OFFICIAL_RECOMMEND.contains("10.0"),
                "官方 recommend 里不该出现 10.0");
    }

    @Test
    @DisplayName("有出口的三条线:9.0 / 10.1 / 11.0")
    void supportedLinesHaveExit() {
        assertEquals("9.0.116", LineTable.lineOf("9.0.115").exitVersion());
        assertEquals("10.1.53", LineTable.lineOf("10.1.52").exitVersion());
        assertEquals("11.0.20", LineTable.lineOf("11.0.18").exitVersion());
    }

    @Test
    @DisplayName("9.0 的 EOL 是未来日期 —— 不能按「有没有 eol 字段」判支持期")
    void ninePointZeroStillSupported() {
        LineTable.Line l = LineTable.lineOf("9.0.115");
        assertNotNull(l.eol(), "9.0 是有 EOL 日期的(2027-03-31)");
        assertTrue(l.supported(), "但那个日期在未来,所以它仍在支持期");
    }

    @Test
    @DisplayName("已 EOL 的线要判成不支持")
    void eolLinesNotSupported() {
        assertFalse(LineTable.lineOf("8.5.100").supported());
        assertFalse(LineTable.lineOf("7.0.109").supported());
    }

    @Test
    @DisplayName("线定位:10.1 不能被 10.0 抢走,反之亦然")
    void lineMatchingIsNotAmbiguous() {
        assertEquals("10.1", LineTable.lineOf("10.1.7").line());
        assertEquals("10.0", LineTable.lineOf("10.0.5").line());
        assertEquals("8.5", LineTable.lineOf("8.5.0").line());
        assertEquals("8.0", LineTable.lineOf("8.0.1").line());
    }

    @Test
    @DisplayName("不认识的版本返回 null,不瞎猜")
    void unknownVersionReturnsNull() {
        assertNull(LineTable.lineOf("6.0.53"));
        assertNull(LineTable.lineOf("12.0.1"));
        assertNull(LineTable.lineOf(null));
        assertNull(LineTable.lineOf(""));
    }

    @Test
    @DisplayName("GitHub 与 Apache 的评级不一致 —— 这本身是本注的一条主张")
    void severityDisagrees() {
        assertEquals("high", LineTable.SEVERITY_GITHUB);
        assertEquals(7.5, LineTable.CVSS_GITHUB, 0.001);
    }
}
