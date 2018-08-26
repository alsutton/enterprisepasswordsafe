package com.enterprisepasswordsafe.engine.nodes;

import com.enterprisepasswordsafe.engine.database.HierarchyNode;
import com.enterprisepasswordsafe.engine.database.HierarchyNodeDAO;

import java.security.GeneralSecurityException;
import java.sql.SQLException;

public class NodeManipulator {

    private HierarchyNodeDAO hierarchyNodeDAO;

    public NodeManipulator() {
        this(HierarchyNodeDAO.getInstance());
    }

    public NodeManipulator(HierarchyNodeDAO hierarchyNodeDAO) {
        this.hierarchyNodeDAO = hierarchyNodeDAO;
    }

    /**
     * Move this node to another parent.
     *
     * @param node The HierarchyNode to move.
     * @param newParent The new parent.
     *
     * @throws SQLException If there is a problem getting accessing the database.
     */

    public void moveTo(final HierarchyNode node, final HierarchyNode newParent)
            throws SQLException, GeneralSecurityException {
        if (newParent == null) {
            throw new GeneralSecurityException("The new parent node does not exist.");
        }

        if (isChild(node, newParent)) {
            throw new GeneralSecurityException("Can not move a node beneath itself.");
        }

        node.setParentId(newParent.getNodeId());
        hierarchyNodeDAO.store(node);
    }

    /**
     * Copy this node to another parent.
     *
     * @param node The node to copy.
     * @param newParentId The ID of the node to put the new copy under.
     *
     * @return The copy of the node.
     *
     * @throws SQLException If there is a problem getting accessing the database.
     * @throws CloneNotSupportedException
     */

    public HierarchyNode copyTo(final HierarchyNode node, final String newParentId)
            throws SQLException, CloneNotSupportedException, GeneralSecurityException {
        if (newParentId == null) {
            throw new GeneralSecurityException("The new parent node does not exist.");
        }

        HierarchyNode newNode = new HierarchyNode(node.getName(), newParentId, node.getType());
        hierarchyNodeDAO.store(newNode);

        return newNode;
    }

    /**
     * Performs a deep copy (i.e. copies a node and all it's children to a new
     * parent).
     *
     * @param node The node to copy.
     * @param newParentId The ID of the node to put the new copy under.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws CloneNotSupportedException
     */

    public void deepCopyTo(final HierarchyNode node, final String newParentId)
            throws SQLException, CloneNotSupportedException, GeneralSecurityException {
        HierarchyNode newParent = hierarchyNodeDAO.getById(newParentId);
        if (newParent == null) {
            throw new GeneralSecurityException("The new parent node does not exist.");
        }

        if (isChild(node, newParent)) {
            throw new GeneralSecurityException("Can not deep copy a node to a place beneath itself.");
        }

        deepCopyToWork(node, newParentId);
    }

    /**
     * Performs a deep copy (i.e. copies a node and all it's children to a new
     * parent).
     *
     * @param node The node to copy.
     * @param newParent The ID of the node to put the new copy under.
     *
     * @throws SQLException Thrown if there is a problem manipulating the database.
     * @throws CloneNotSupportedException
     */

    private void deepCopyToWork(final HierarchyNode node, final String newParent)
            throws SQLException, CloneNotSupportedException, GeneralSecurityException {
        copyTo(node, newParent);

        for(HierarchyNode thisNode : hierarchyNodeDAO.getAllChildren(node)) {
            deepCopyToWork(thisNode, newParent);
        }
    }


    /**
     * Checks if this node is the parent of another node.
     *
     * @param parent The parent to be tested for
     * @param child The child to check.
     *
     * @return true if this node is a child of the specified node, false if not.
     *
     * @throws SQLException
     *             Thrown if there is a problem accessing the database.
     */

    public boolean isChild(final HierarchyNode parent, final HierarchyNode child)
            throws SQLException {
        final String parentId = parent.getNodeId();
        if (parentId.equals(HierarchyNode.ROOT_NODE_ID)) {
            return true;
        }
        if (child.getNodeId().equals(HierarchyNode.ROOT_NODE_ID)) {
            return false;
        }
        if (child.getParentId().equals(parentId)) {
            return true;
        }
        if (parent.equals(child)) {
            return true;
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

}
