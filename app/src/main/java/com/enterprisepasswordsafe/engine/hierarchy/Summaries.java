package com.enterprisepasswordsafe.engine.hierarchy;

import com.enterprisepasswordsafe.database.HierarchyNode;
import com.enterprisepasswordsafe.database.HierarchyNodeDAO;
import com.enterprisepasswordsafe.database.derived.HierarchyNodeSummary;
import com.enterprisepasswordsafe.database.derived.ImmutableHierarchyNodeSummary;

import java.sql.SQLException;

public class Summaries {

    final HierarchyTools hierarchyTools;
    final HierarchyNodeDAO hierarchyNodeDAO;

    public Summaries() {
        hierarchyTools = new HierarchyTools();
        hierarchyNodeDAO = HierarchyNodeDAO.getInstance();
    }

    public HierarchyNodeSummary getSummary(final HierarchyNode node )
            throws SQLException {
        String nodeId = node.getNodeId();

        return ImmutableHierarchyNodeSummary.builder()
                .id(nodeId)
                .parentage(hierarchyTools.getParentageAsText(node))
                .build();
    }

    /**
     * Get the summary for a node given its' ID.
     *
     * @param nodeId The node to get the summary of.
     */

    public HierarchyNodeSummary getSummary( final String nodeId )
            throws SQLException {
        return getSummary(hierarchyNodeDAO.getById(nodeId));
    }
}
