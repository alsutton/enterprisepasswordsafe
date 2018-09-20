package com.enterprisepasswordsafe.engine.hierarchy;

import com.enterprisepasswordsafe.engine.database.*;
import com.enterprisepasswordsafe.engine.database.actions.NodeObjectAction;
import com.enterprisepasswordsafe.engine.database.derived.HierarchyNodeChildren;
import javafx.scene.Parent;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.*;

public class HierarchyTools {

    private HierarchyNodeDAO hierarchyNodeDAO;

    public HierarchyTools() {
        hierarchyNodeDAO = HierarchyNodeDAO.getInstance();
    }

    public List<HierarchyNode> getParentage(final HierarchyNode node)
            throws SQLException {
        final List<HierarchyNode> parentage = new ArrayList<HierarchyNode>();
        String currentNodeId = node.getParentId();
        while (currentNodeId != null ) {
            HierarchyNode thisNode = hierarchyNodeDAO.getById(currentNodeId);
            parentage.add(0, thisNode);
            currentNodeId = thisNode.getParentId();
        }

        return parentage;
    }

    public String getParentageAsText(final HierarchyNode node)
            throws SQLException {
        StringBuilder parentageText = new StringBuilder();

        for( HierarchyNode thisNode : getParentage(node) ) {
            parentageText.append(thisNode.getName());
            parentageText.append(" \\ ");
        }
        parentageText.append(node.getName());

        return parentageText.toString();
    }

    public HierarchyNodeChildren getChildrenValidForUser(final HierarchyNode node, final User theUser, boolean includeEmpty,
                                                         final Comparator<HierarchyNode> nodeComparator, final Comparator<Password> objectComparator)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        Collection<HierarchyNode> containers =
                hierarchyNodeDAO.getChildrenContainerNodesForUser(node, theUser, includeEmpty, nodeComparator);
        Set<Password> objects =
                hierarchyNodeDAO.getAllChildrenObjects(node, theUser, objectComparator);

        return new HierarchyNodeChildren(containers, objects);
    }

    public void processObjectNodes(final HierarchyNode node, final User theUser,
                                   final NodeObjectAction action, final boolean recurse)
            throws Exception {
        if(recurse) {
            for( HierarchyNode thisNode : hierarchyNodeDAO.getChildrenContainerNodesForUser(node, theUser, true, null)) {
                processObjectNodes(thisNode, theUser, action, true);
            }
        }

        for(AccessControledObject aco: hierarchyNodeDAO.getAllChildrenObjects(node, theUser, null)) {
            action.process(node, aco);
        }
    }

    public boolean isPersonalByName(final String name) throws SQLException {
        return isPersonalById( hierarchyNodeDAO.getByName(name).getNodeId() );
    }

    public boolean isPersonalById(final String id) throws SQLException {
        HierarchyNode node = hierarchyNodeDAO.getById(id);
        boolean result;
        if( node.getParentId() != null ) {
            result = isPersonalById(node.getParentId());
        } else {
            result = (!node.getNodeId().equals(HierarchyNode.ROOT_NODE_ID));
        }

        return result;
    }

}
