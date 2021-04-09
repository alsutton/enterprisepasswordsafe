package com.enterprisepasswordsafe.engine.nodes;

import com.enterprisepasswordsafe.model.dao.HierarchyNodeDAO;
import com.enterprisepasswordsafe.model.persisted.HierarchyNode;

import java.security.GeneralSecurityException;
import java.sql.SQLException;

public abstract class HierarchyManipulator {

    final HierarchyNodeDAO hierarchyNodeDAO;

    public HierarchyManipulator() {
        this(HierarchyNodeDAO.getInstance());
    }

    public HierarchyManipulator(HierarchyNodeDAO hierarchyNodeDAO) {
        this.hierarchyNodeDAO = hierarchyNodeDAO;
    }

    public abstract void performAction(final HierarchyNode node, final HierarchyNode newParent)
            throws SQLException, GeneralSecurityException;

    void ensureParentIsValid(final HierarchyNode newParent)
            throws GeneralSecurityException {
        if (newParent == null) {
            throw new GeneralSecurityException("The new parent node does not exist.");
        }
    }

    void ensureOperationWontCauseInfiniteRecursion(final HierarchyNode node, final HierarchyNode newParent)
            throws GeneralSecurityException, SQLException {
        if (isChild(node, newParent)) {
            throw new GeneralSecurityException("Can not deep copy a node to a place beneath itself.");
        }
    }

    boolean isChild(final HierarchyNode parent, final HierarchyNode child)
            throws SQLException {
        final String parentId = parent.getNodeId();
        if (parentId.equals(HierarchyNode.ROOT_NODE_ID) || child.getParentId().equals(parentId)
        ||  parent.equals(child)) {
            return true;
        }
        if (child.getNodeId().equals(HierarchyNode.ROOT_NODE_ID)) {
            return false;
        }

        String currentParentId = child.getParentId();
        while(!currentParentId.equals(HierarchyNode.ROOT_NODE_ID)) {
            final HierarchyNode thisParent = hierarchyNodeDAO.getById(currentParentId);
            final String thisParentId = thisParent.getNodeId();
            if( thisParentId.equals(parentId)) {
                return true;
            }
            currentParentId = thisParentId;
        }

        return false;
    }


    // Move a node to another target
    public static class MoveNodeManipulator extends HierarchyManipulator {
        public MoveNodeManipulator(HierarchyNodeDAO hierarchyNodeDAO) {
            super(hierarchyNodeDAO);
        }

        public void performAction(final HierarchyNode node, final HierarchyNode newParent)
                throws SQLException, GeneralSecurityException {
            ensureParentIsValid(newParent);
            ensureOperationWontCauseInfiniteRecursion(node, newParent);
            node.setParentId(newParent.getNodeId());
            hierarchyNodeDAO.store(node);
        }
    }

    // Copy the node to another parent
    public static class CopyNodeManipulator extends HierarchyManipulator {
        public CopyNodeManipulator(HierarchyNodeDAO hierarchyNodeDAO) {
            super(hierarchyNodeDAO);
        }

        public void performAction(final HierarchyNode node, final HierarchyNode newParent)
                throws SQLException, GeneralSecurityException {
            ensureParentIsValid(newParent);
            performCopy(node, newParent);
        }

        HierarchyNode performCopy(final HierarchyNode node, final HierarchyNode newParent)
                throws SQLException {
            HierarchyNode newNode = new HierarchyNode(node.getName(), newParent.getNodeId(), node.getType());
            hierarchyNodeDAO.store(newNode);
            return newNode;
        }
    }

    // Copy the node and all subnodes to another location
    public static class DeepCopyNodeManipulator extends CopyNodeManipulator {
        public DeepCopyNodeManipulator(HierarchyNodeDAO hierarchyNodeDAO) {
            super(hierarchyNodeDAO);
        }

        public void performAction(final HierarchyNode node, final HierarchyNode newParent)
            throws SQLException, GeneralSecurityException {
            ensureParentIsValid(newParent);
            ensureOperationWontCauseInfiniteRecursion(node, newParent);
            deepCopyToWork(node, newParent);
        }

        private void deepCopyToWork(final HierarchyNode node, final HierarchyNode newParent)
                throws SQLException {
            HierarchyNode newNode = performCopy(node, newParent);
            for(HierarchyNode thisNode : hierarchyNodeDAO.getAllChildren(node)) {
                deepCopyToWork(thisNode, newParent);
            }
        }
    }
}
