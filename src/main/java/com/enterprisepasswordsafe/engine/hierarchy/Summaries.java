package com.enterprisepasswordsafe.engine.hierarchy;

import com.enterprisepasswordsafe.engine.database.HierarchyNode;
import com.enterprisepasswordsafe.engine.database.HierarchyNodeDAO;
import com.enterprisepasswordsafe.engine.database.derived.HierarchyNodeSummary;

import java.sql.SQLException;

public class Summaries {

    HierarchyTools hierarchyTools;
    HierarchyNodeDAO hierarchyNodeDAO;

    public Summaries() {
        hierarchyTools = new HierarchyTools();
        hierarchyNodeDAO = HierarchyNodeDAO.getInstance();
    }

    public HierarchyNodeSummary getSummary(final HierarchyNode node )
            throws SQLException {
        String nodeId = node.getNodeId();

        return new HierarchyNodeSummary(nodeId, hierarchyTools.getParentageAsText(node));
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
