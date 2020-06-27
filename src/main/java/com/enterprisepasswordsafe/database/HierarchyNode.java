/*
 * Copyright (c) 2017 Carbon Security Ltd. <opensource@carbonsecurity.co.uk>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package com.enterprisepasswordsafe.database;

import com.enterprisepasswordsafe.engine.utils.IDGenerator;

import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Representation of a node in the hierarchy.
 */
public final class HierarchyNode
	implements Cloneable, Comparable<HierarchyNode> {
	
    /**
     * The ID of the root node.
     */

    public static final String ROOT_NODE_ID = "0";
    
    /**
     * The columns in the database table holding data about a hierarchy node..
     */

    public static final String NODE_FIELDS = " nodes.node_id, nodes.name, nodes.parent_id, nodes.type ";

    /**
     * Type marker for a container node.
     */

    public static final int CONTAINER_NODE = 0;

    /**
     * Type marker for a node holding object information.
     */

    public static final int OBJECT_NODE = 1;

    /**
     * Type marker for a user container node.
     */

    public static final int USER_CONTAINER_NODE = 2;

    /**
     * The id of this node.
     */

    private String nodeId;

    /**
     * The name of this node.
     */

    private String name;

    /**
     * The parent of this node.
     */

    private String parentId;

    /**
     * The type of this node.
     */

    private int type;

    /**
     * Creates an instance of the root node.
     */

    protected HierarchyNode() {
        nodeId = HierarchyNode.ROOT_NODE_ID;
        name = "Top Level";
        parentId = null;
        type = HierarchyNode.CONTAINER_NODE;
    }

    /**
     * Creates a new Node instance from the data supplied.
     *
     * @param newName
     *            The name of this node.
     * @param newParentId
     *            The ID of the parent for this node.
     * @param newType
     *            The type of node this is.
     */

    public HierarchyNode(final String newName, final String newParentId,
            final int newType) {
        nodeId = IDGenerator.getID();
        name = newName;
        type = newType;

        parentId = newParentId;
        if (parentId == null) {
            parentId = HierarchyNode.ROOT_NODE_ID;
        }
    }

    /**
     * Extracts the information about this node from the JDBC ResultSet.
     *
     * @param rs
     *            The result set to extract the data from.
     * @param startIdx
     *            The start index for the node information.
     *
     * @throws SQLException
     *             Thrown if there is a problem extracting the information.
     */

    public HierarchyNode(final ResultSet rs, final int startIdx)
        throws SQLException {
        int idx = startIdx;
        nodeId = rs.getString(idx++);
        name = rs.getString(idx++);
        parentId = rs.getString(idx++);
        type = rs.getInt(idx);
    }
    
    /**
     * Compare to another object.
     *
     * @param otherNode
     *            The other object.
     *
     * @return The result of comparing the names of the nodes.
     */
    public int compareTo(final HierarchyNode otherNode) {
        if(name == null && otherNode.name == null) {
        	return 0;
        }
        if(name == null) {
        	return Integer.MIN_VALUE;
        }
        if(otherNode.name == null) {
        	return Integer.MAX_VALUE;
        }
        return name.compareTo(otherNode.name);
    }

    /**
     * Gets the name of the node.
     *
     * @return The name of the node.
     */

    public String getName() {
        return name;
    }

    /**
     * @return Returns the nodeId.
     */
    public String getNodeId() {
        return nodeId;
    }
    
	public String getParentId() {
		return parentId;
	}

	public void setParentId(String parentId) {
		this.parentId = parentId;
	}

	public int getType() {
		return type;
	}

	public void setType(int type) {
		this.type = type;
	}
}
