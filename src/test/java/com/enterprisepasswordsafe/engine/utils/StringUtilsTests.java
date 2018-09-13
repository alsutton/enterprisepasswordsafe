package com.enterprisepasswordsafe.engine.utils;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class StringUtilsTests {

    @Test
    private void testLeadingWhitespaceRemoval() {
        Assertions.assertEquals("1", StringUtils.removeLeadingAndTailingWhitespace(" 1"));
    }

    @Test
    private void testTrailingWhitespaceRemoval() {
        Assertions.assertEquals("1", StringUtils.removeLeadingAndTailingWhitespace("1 "));
    }

    @Test
    private void testWhitespaceRemovalBothEnds() {
        Assertions.assertEquals("1", StringUtils.removeLeadingAndTailingWhitespace(" 1 "));
    }

    @Test
    private void testWhitespaceRemovalEmptiesString() {
        Assertions.assertEquals("", StringUtils.removeLeadingAndTailingWhitespace("  "));
    }

    @Test
    private void testWhitespaceRemovalNullHandling() {
        Assertions.assertEquals(null, StringUtils.removeLeadingAndTailingWhitespace(null));
    }

    @Test
    private void testIsEmptyIdentifiesEmptyStrings() {
        Assertions.assertTrue(StringUtils.isEmpty(""));
    }

    @Test
    private void testIsEmptyIdentifiesNulls() {
        Assertions.assertTrue(StringUtils.isEmpty(null));
    }

    @Test
    private void testIsEmptyIdentifiesNonEmptyStrings() {
        Assertions.assertFalse(StringUtils.isEmpty("1"));
    }

    @Test
    private void testIsAnyEmptySpotsAnEmpty() {
        Assertions.assertTrue(StringUtils.isAnyEmpty("1", "", "2"));
    }
}
