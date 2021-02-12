package com.enterprisepasswordsafe.database.derived;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class HierarchyNodeSummaryTest {

    @Test
    public void testEqualsIsTrueForEquivalentId() {
        HierarchyNodeSummary first = new HierarchyNodeSummary("id", "parent1");
        HierarchyNodeSummary second = new HierarchyNodeSummary("id", "parent1");

        Assertions.assertEquals(second, first);
    }

    @Test
    public void testEqualsIsFalseForDifferedId() {
        HierarchyNodeSummary first = new HierarchyNodeSummary("id", "parent1");
        HierarchyNodeSummary second = new HierarchyNodeSummary("id2", "parent1");

        Assertions.assertNotEquals(second, first);
    }

    @Test
    public void testCompareIsZeroForTheSameParent() {
        HierarchyNodeSummary first = new HierarchyNodeSummary("id", "parent1");
        HierarchyNodeSummary second = new HierarchyNodeSummary("id", "parent1");

        Assertions.assertEquals(0, first.compareTo(second));
    }

    @Test
    public void testCompareLessThanZeroForEarlierParent() {
        HierarchyNodeSummary first = new HierarchyNodeSummary("id", "parent1");
        HierarchyNodeSummary second = new HierarchyNodeSummary("id2", "parent2");

        Assertions.assertTrue(first.compareTo(second) < 0);
    }

    @Test
    public void testCompareGreaterThanZeroForLaterParent() {
        HierarchyNodeSummary first = new HierarchyNodeSummary("id", "parent2");
        HierarchyNodeSummary second = new HierarchyNodeSummary("id2", "parent1");

        Assertions.assertTrue(first.compareTo(second) > 0);
    }
}
