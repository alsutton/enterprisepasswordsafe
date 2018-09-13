package com.enterprisepasswordsafe.engine.utils;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class StringUtilsTests {

    @Test
    public void testLeadingWhitespaceRemoval() {
        Assertions.assertEquals("1", StringUtils.removeLeadingAndTailingWhitespace(" 1"));
    }

    @Test
    public void testTrailingWhitespaceRemoval() {
        Assertions.assertEquals("1", StringUtils.removeLeadingAndTailingWhitespace("1 "));
    }

    @Test
    public void testWhitespaceRemovalBothEnds() {
        Assertions.assertEquals("1", StringUtils.removeLeadingAndTailingWhitespace(" 1 "));
    }

    @Test
    public void testWhitespaceRemovalEmptiesString() {
        Assertions.assertEquals("", StringUtils.removeLeadingAndTailingWhitespace("  "));
    }

    @Test
    public void testWhitespaceRemovalNullHandling() {
        Assertions.assertEquals(null, StringUtils.removeLeadingAndTailingWhitespace(null));
    }

    @Test
    public void testIsEmptyIdentifiesEmptyStrings() {
        Assertions.assertTrue(StringUtils.isEmpty(""));
    }

    @Test
    public void testIsEmptyIdentifiesNulls() {
        Assertions.assertTrue(StringUtils.isEmpty(null));
    }

    @Test
    public void testIsEmptyIdentifiesNonEmptyStrings() {
        Assertions.assertFalse(StringUtils.isEmpty("1"));
    }

    @Test
    public void testIsAnyEmptySpotsAnEmpty() {
        Assertions.assertTrue(StringUtils.isAnyEmpty("1", "", "2"));
    }

    @Test
    public void testIsAnyEmptyIdentifiesNoneCorrectly() {
        Assertions.assertFalse(StringUtils.isAnyEmpty("1", "2", "3"));
    }}
