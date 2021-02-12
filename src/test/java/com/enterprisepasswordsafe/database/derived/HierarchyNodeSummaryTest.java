package com.enterprisepasswordsafe.database.derived;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class HierarchyNodeSummaryTest {

    private ImmutableHierarchyNodeSummary build(String id, String parentage) {
        return ImmutableHierarchyNodeSummary.builder()
                .id(id)
                .parentage(parentage)
                .build();
    }

    @Test
    public void testEqualsIsTrueForEquivalentId() {
        ImmutableHierarchyNodeSummary first = build("id", "parent1");
        ImmutableHierarchyNodeSummary second = build("id", "parent1");

        Assertions.assertEquals(second, first);
    }

    @Test
    public void testEqualsIsFalseForDifferedId() {
        ImmutableHierarchyNodeSummary first = build("id", "parent1");
        ImmutableHierarchyNodeSummary second = build("id2", "parent1");

        Assertions.assertNotEquals(second, first);
    }

    @Test
    public void testCompareIsZeroForTheSameParent() {
        ImmutableHierarchyNodeSummary first = build("id", "parent1");
        ImmutableHierarchyNodeSummary second = build("id", "parent1");

        Assertions.assertEquals(0, first.compareTo(second));
    }

    @Test
    public void testCompareLessThanZeroForEarlierParent() {
        ImmutableHierarchyNodeSummary first = build("id", "parent1");
        ImmutableHierarchyNodeSummary second = build("id2", "parent2");

        Assertions.assertTrue(first.compareTo(second) < 0);
    }

    @Test
    public void testCompareGreaterThanZeroForLaterParent() {
        ImmutableHierarchyNodeSummary first = build("id", "parent2");
        ImmutableHierarchyNodeSummary second = build("id2", "parent1");

        Assertions.assertTrue(first.compareTo(second) > 0);
    }
}
