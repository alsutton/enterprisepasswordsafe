package com.enterprisepasswordsafe.engine.hierarchy;

import com.enterprisepasswordsafe.database.AccessControlDAO;
import com.enterprisepasswordsafe.database.HierarchyNode;
import com.enterprisepasswordsafe.database.HierarchyNodeDAO;
import com.enterprisepasswordsafe.database.User;
import com.enterprisepasswordsafe.engine.accesscontrol.AccessControl;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;

public class NodeDeleter {

    private HierarchyNodeDAO hierarchyNodeDAO;

    public NodeDeleter() {
        hierarchyNodeDAO = HierarchyNodeDAO.getInstance();
    }

    public void deleteNodes(final User deletingUser, final HierarchyNode parent, final String[] nodes)
            throws SQLException, GeneralSecurityException, IOException {
        validateSelectedNodes(deletingUser, parent, nodes);
        deleteSpecifiedNodes(deletingUser, parent, nodes);
    }

    private void validateSelectedNodes(User deletingUser, HierarchyNode parent, String[] nodes)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        for (String thisNodeId : nodes) {
            if (thisNodeId != null && thisNodeId.startsWith("p_")) {
                thisNodeId = hierarchyNodeDAO.getNodeIDForObject(parent.getNodeId(), thisNodeId.substring(2));
            }
            if (thisNodeId == null) {
                continue;
            }
            HierarchyNode thisNode = hierarchyNodeDAO.getById(thisNodeId);
            if (thisNode == null) {
                continue;
            }

            if (isNotDeletableByUser(deletingUser, thisNode)) {
                throw new RuntimeException(
                        "Delete failed, You do not have the permissions needed to delete all the objects specified.");
            }
        }
    }

    private boolean isNotDeletableByUser(final User user, final HierarchyNode node)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        if(node.getType() == HierarchyNode.OBJECT_NODE) {
            AccessControl ac = AccessControlDAO.getInstance().getAccessControl(user, node.getName());
            return (ac != null && ac.getModifyKey() != null);
        }

        for(HierarchyNode thisNode : hierarchyNodeDAO.getAllChildren(node)) {
            if(isNotDeletableByUser(user,thisNode)) {
                return false;
            }
        }

        return true;
    }

    private void deleteSpecifiedNodes(User deletingUser, HierarchyNode parent, String[] nodes)
            throws GeneralSecurityException, SQLException, IOException {
        for (String thisNodeId : nodes) {
            if (thisNodeId != null && thisNodeId.startsWith("p_")) {
                thisNodeId = hierarchyNodeDAO.getNodeIDForObject(parent.getNodeId(), thisNodeId.substring(2));
            }
            if (thisNodeId == null) {
                continue;
            }

            HierarchyNode thisNode = hierarchyNodeDAO.getById(thisNodeId);
            if (thisNode != null) {
                hierarchyNodeDAO.deleteNode(thisNode, deletingUser);
            }
        }

    }
}
