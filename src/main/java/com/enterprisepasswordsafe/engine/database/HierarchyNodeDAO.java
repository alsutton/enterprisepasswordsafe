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

package com.enterprisepasswordsafe.engine.database;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.enterprisepasswordsafe.engine.database.actions.NodeObjectAction;
import com.enterprisepasswordsafe.engine.database.derived.GroupSummary;
import com.enterprisepasswordsafe.engine.database.derived.HierarchyNodeChildren;
import com.enterprisepasswordsafe.engine.database.derived.HierarchyNodeSummary;
import com.enterprisepasswordsafe.engine.database.derived.UserSummary;
import com.enterprisepasswordsafe.engine.utils.Cache;
import com.enterprisepasswordsafe.engine.utils.DatabaseConnectionUtils;
import com.enterprisepasswordsafe.proguard.ExternalInterface;
import com.enterprisepasswordsafe.proguard.JavaBean;

/**
 * Data access object for nodes in the hierarchy.
 */
public final class HierarchyNodeDAO
    extends ObjectFetcher<HierarchyNode>
    implements ExternalInterface {

	/**
     * The shared root node.
     */

    private static final HierarchyNode ROOT_NODE = new HierarchyNode();

    private static final String NODE_FIELDS = "node_id, name, parent_id, type";

    /**
     * SQL to get the parent ID of a node from its ID.
     */

    private static final String GET_NODE_PARENT_ID_SQL = "SELECT parent_id FROM hierarchy WHERE node_id = ? ";

    /**
     * SQL To get a node from its' ID.
     */

    private static final String GET_NODE_BY_ID_SQL =
            "SELECT " + NODE_FIELDS + " FROM hierarchy WHERE node_id = ?";

    /**
     * The SQL statement to get the nodes representing a specific access controlled object.
     */

    private static final String GET_NODE_BY_NAME_SQL =
            "SELECT " + NODE_FIELDS + " FROM hierarchy  WHERE name = ?";


    /**
     * The SQL statement to get the child nodes of a specific node.
     */

    private static final String GET_ALL_CHILDREN_NODES_SQL =
            "SELECT node_id, name, parent_id, type FROM hierarchy nodes WHERE parent_id = ? ";

    /**
     * The SQL statement to get the nodes representing a specific access controlled object.
     */

    private static final String GET_NODE_ID_FOR_CHILD_OBJECT_ID_SQL =
            "SELECT node_id "
            + "  FROM hierarchy "
            + " WHERE parent_id = ? "
            + "   AND name = ? "
            + "   AND type = " + HierarchyNode.OBJECT_NODE;

    /**
     * The SQL statement to get the nodes representing a specific access controlled object.
     */

    private static final String GET_DEFAULT_PASSWORD_PERMISSIONS_FOR_NODE =
            "SELECT type, actor_id, permission"
            + "  FROM hierarchy_password_defaults "
            + " WHERE node_id = ? ";

    /**
     * The SQL statement to get the nodes representing a specific access controlled object.
     */

    private static final String DELETE_PASSWORD_DEFAULTS_FOR_NODE =
            "DELETE FROM hierarchy_password_defaults WHERE node_id = ? ";

    /**
     * The SQL statement to get the nodes representing a specific access controlled object.
     */

    private static final String SET_PASSWORD_DEFAULTS_FOR_NODE =
            "INSERT INTO hierarchy_password_defaults(node_id, type, actor_id, permission) "+
            "								VALUES  (      ?,    ?,        ?,          ?) ";

    /**
     * The SQL statement to get the all child object node ids.
     */

    private static final String GET_CHILD_OBJECTS_SQL =
            "SELECT   " + PasswordDAO.PASSWORD_FIELDS
            + "  FROM hierarchy h, passwords pass"
            + " WHERE h.parent_id = ? "
            + "   AND h.type = " + HierarchyNode.OBJECT_NODE
            + "   AND h.name = pass.password_id";

    /**
     * The SQL statement to get the valid object node children for a given
     * user where the user has user access control access.
     */

    private static final String GET_VALID_CHILD_OBJECT_IDS_VIA_UAC_SQL =
            "SELECT   h.name "
            + "  FROM hierarchy h, "
            + "       user_access_control uac "
            + " WHERE h.parent_id = ? "
            + "  AND h.type = " + HierarchyNode.OBJECT_NODE
            + "  AND uac.item_id = h.name "
            + "  AND uac.rkey is not null "
            + "  AND uac.user_id = ? ";

    /**
     * The SQL statement to get the valid object node children for a given
     * user where the user has user access control access.
     */

    private static final String GET_VALID_CHILD_OBJECT_IDS_VIA_GAC_SQL =
            "SELECT   h.name "
            + "  FROM hierarchy h, "
            + "       group_access_control gac, "
            + "       membership m, "
            + "       groups g "
            + " WHERE h.parent_id = ? "
            + "   AND h.type = "+ HierarchyNode.OBJECT_NODE+ " "
            + "   AND gac.item_id = h.name "
            + "   AND gac.rkey is not null "
            + "   AND m.group_id = gac.group_id "
            + "   AND m.user_id = ? "
            + "   AND g.group_id = gac.group_id "
            + "   AND g.status = " + Group.STATUS_ENABLED;

    /**
     * The SQL statement to get the all child object node ids.
     */

    private static final String GET_CHILD_OBJECTS_VIA_UAC_SQL =
            "SELECT   " + UserAccessControlDAO.UAC_FIELDS+", "+PasswordDAO.PASSWORD_FIELDS
            + "  FROM hierarchy h, "
            + "       passwords pass, "
            + "       user_access_control uac "
            + " WHERE h.parent_id = ? "
            + "  AND h.type = " + HierarchyNode.OBJECT_NODE
            + "  AND uac.item_id = h.name "
            + "  AND uac.rkey is not null "
            + "  AND uac.user_id = ? "
            + "  AND pass.password_id = h.name";

    /**
     * The SQL statement to get the valid object node children for a given
     * user where the user has user access control access.
     */

    private static final String GET_CHILD_OBJECTS_VIA_GAC_SQL =
            "SELECT   " + GroupAccessControlDAO.GAC_FIELDS +", "+PasswordDAO.PASSWORD_FIELDS
            + "  FROM hierarchy h, "
            + "       passwords pass, "
            + "       group_access_control gac, "
            + "       membership m, "
            + "       groups g "
            + " WHERE h.parent_id = ? "
            + "   AND h.type = "+ HierarchyNode.OBJECT_NODE+ " "
            + "   AND pass.password_id = h.name"
            + "   AND gac.item_id = h.name "
            + "   AND gac.rkey is not null "
            + "   AND m.group_id = gac.group_id "
            + "   AND m.user_id = ? "
            + "   AND g.group_id = gac.group_id "
            + "   AND g.status = " + Group.STATUS_ENABLED;


    /**
     * The SQL statement to get the child container nodes of a specific node.
     */

    private static final String GET_CHILDREN_NODES_SQL =
            "SELECT   node_id, name, parent_id, type"
            + "  FROM hierarchy"
            + " WHERE parent_id = ? "
            + "   AND type=" + HierarchyNode.CONTAINER_NODE;


    /**
     * The SQL statement to get the child container nodes of a specific node.
     */

    private static final String GET_CHILDREN_NODE_IDS_SQL =
            "SELECT   node_id"
            + "  FROM hierarchy"
            + " WHERE parent_id = ? "
            + "   AND type=" + HierarchyNode.CONTAINER_NODE;

    /**
     * The SQL statement to get the user node for a user
     */

    private static final String GET_USER_CONTAINER_NODE_SQL =
            "SELECT   node_id, name, parent_id, type "
            + "  FROM hierarchy"
            + " WHERE name = ? "
            + "   AND type = " + HierarchyNode.USER_CONTAINER_NODE;

    /**
     * The SQL statement to get the child container nodes of a specific node.
     */

    private static final String GET_CHILD_BY_NAME_SQL =
            "SELECT   node_id"
            + "  FROM hierarchy"
            + " WHERE parent_id = ? "
            + "   AND name = ?";

    /**
     * The SQL statement to write a new node to the database.
     */

    private static final String INSERT_NODE_SQL =
            "INSERT INTO hierarchy( name, parent_id, type, node_id ) "
            + "            VALUES (    ?,         ?,    ?,       ? ) ";

    /**
     * The SQL statement to update a node in the hierarchy.
     */

    private static final String UPDATE_NODE_SQL =
            "UPDATE hierarchy "
            + "   SET name = ?, parent_id = ?, type = ? "
            + " WHERE node_id = ?";

    /**
     * SQL to count the number of nodes referring to a object.
     */

    private static final String TEST_NODES_REFERRING_TO_OBJECT_NODE_SQL =
            "SELECT node_id "
            + "  FROM hierarchy "
            + " WHERE name = ?"
            + "   AND type = " + HierarchyNode.OBJECT_NODE;

    /**
     * The SQL to delete a node.
     */

    private static final String DELETE_SQL = "DELETE FROM hierarchy WHERE node_id = ?";

    /**
     * The SQL to get the user summary for a search
     */

    private static final String GET_PERMISSION_SUMMARY_FOR_USER =
    		"SELECT   hpd.permission "
    		+ "  FROM hierarchy_password_defaults hpd"
            + " WHERE hpd.actor_id = ? "
            + "   AND hpd.node_id = ?"
            + "   AND hpd.type = 'u'";

    /**
     * The SQL to get the user summary for a search
     */

    private static final String GET_PERMISSION_SUMMARY_FOR_GROUP =
    		"SELECT   hpd.permission "
    		+ "  FROM hierarchy_password_defaults hpd"
            + " WHERE hpd.actor_id = ? "
            + "   AND hpd.node_id = ?"
            + "   AND hpd.type = 'g'";

    /**
     * Cache for node summaries.
     */

    private final Cache<String,HierarchyNodeSummary> summaryCache = new Cache<String,HierarchyNodeSummary>();

	/**
	 * The cache of personal and non-personal nodes.
	 */

	private Cache<String,Boolean> personalNodeCache;

	/**
	 * Private constructor to prevent instantiation
	 */

	private HierarchyNodeDAO( ) {
		super(GET_NODE_BY_ID_SQL, GET_NODE_BY_NAME_SQL, DELETE_SQL);
	}

    @Override
    HierarchyNode newInstance(ResultSet rs, int startIndex)
            throws SQLException {
        return new HierarchyNode(rs, startIndex);
    }

    /**
	 * Create a new hierarchy node
	 */

    public HierarchyNode create (final String name, final String parentId, final int type)
    	throws SQLException, GeneralSecurityException {
    	if( childAlreadyExists( parentId, name ) ) {
    		throw new GeneralSecurityException ("A node with that name already exists");
    	}
    	HierarchyNode node = new HierarchyNode(name, parentId, type);
    	store(node);
    	return node;
    }

    /**
     * Store the details of a HierarchyNode in the database.
     *
     * @param node The node to store.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     */

    public void store(final HierarchyNode node)
        throws SQLException {
        String statementSQL = INSERT_NODE_SQL;

        if (getById(node.getNodeId()) != null) {
            statementSQL = UPDATE_NODE_SQL;
        }

        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(statementSQL);
        try {
            ps.setString(1, node.getName());
            ps.setString(2, node.getParentId());
            ps.setInt   (3, node.getType());
            ps.setString(4, node.getNodeId());
            ps.executeUpdate();
        } finally {
            DatabaseConnectionUtils.close(ps);
        }
    }

    /**
     * Gets a specific node.
     *
     * @param nodeId The ID of the node to get.
     *
     * @return The requested node, or null if it doesn't exist.
     *
     * @throws SQLException Thrown if there is problem talking to the database.
     */

    public HierarchyNode getById(final String nodeId)
            throws SQLException {
        return (nodeId == null || nodeId.equals(HierarchyNode.ROOT_NODE_ID)) ? ROOT_NODE : super.getById(nodeId);
    }


    /**
     * Gets the ID of the parent of a node.
     *
     * @param nodeId The ID of the node to get the parent of.
     *
     * @return The ID of the nodes parent.
     *
     * @throws SQLException Thrown if there is problem talking to the database.
     */

    public String getParentIdById(final String nodeId)
            throws SQLException {
        if (nodeId == null || nodeId.equals(HierarchyNode.ROOT_NODE_ID)) {
            return null;
        }

        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_NODE_PARENT_ID_SQL);
        try {
            ps.setString(1, nodeId);
            ps.setMaxRows(1);

            ResultSet rs = ps.executeQuery();
            try {
	            if (rs.next()) {
	                return rs.getString(1);
	            }

	            return null;
            } finally {
            	DatabaseConnectionUtils.close(rs);
            }
        } finally {
            DatabaseConnectionUtils.close(ps);
        }
    }

    /**
     * Gets a specific child node by it's name.
     *
     * @param parentId The ID of the parent of the requested node.
     * @param name The name of the node to check for
     *
     * @return The requested node, or null if it doesn't exist.
     *
     * @throws SQLException
     *             Thrown if there is problem talking to the database.
     */

    public boolean childAlreadyExists(final String parentId, final String name)
            throws SQLException {
    	// TODO Use more efficient SQL which only returns 1 item.
        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_CHILD_BY_NAME_SQL);
        try {
            ps.setString(1, parentId);
            ps.setString(2, name);

            ResultSet rs = ps.executeQuery();
            try {
            	return rs.next();
            } finally {
            	DatabaseConnectionUtils.close(rs);
            }
        } finally {
        	DatabaseConnectionUtils.close(ps);
        }
    }

    /**
     * Delete a node.
     *
     * @param node The node to delete.
     * @param deletingUser The user who deleted the node.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if tehre is a problem with the log entry.
     * @throws UnsupportedEncodingException
     */

    public void deleteNode(final HierarchyNode node, final User deletingUser)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        if (node.getType() == HierarchyNode.CONTAINER_NODE) {
            // Look for children nodes to recursively delete
            PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_ALL_CHILDREN_NODES_SQL);
            ResultSet rs = null;
            try {
                ps.setString(1, node.getNodeId());
                rs = ps.executeQuery();
                while (rs.next()) {
                    HierarchyNode thisNode = new HierarchyNode(rs, 1);
                    deleteNode(thisNode, deletingUser);
                }

                TamperproofEventLogDAO.getInstance().create(
                		TamperproofEventLog.LOG_LEVEL_HIERARCHY_MANIPULATION,
                		deletingUser,
                		null,
                		"Deleted Node " +
                			node.getName() +
                			" from {node:"
                			+ node.getNodeId()
                			+ "}",
                		true
            		);
            } finally {
                DatabaseConnectionUtils.close(rs);
                DatabaseConnectionUtils.close(ps);
            }
        }

        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(DELETE_SQL);
        try {
            ps.setString(1, node.getNodeId());
            ps.executeUpdate();
        } finally {
            DatabaseConnectionUtils.close(ps);
        }

        if (node.getType()== HierarchyNode.OBJECT_NODE) {
            ResultSet rs = null;
            ps = BOMFactory.getCurrentConntection().prepareStatement(TEST_NODES_REFERRING_TO_OBJECT_NODE_SQL);
            try {
            	ps.setMaxRows(1);
                ps.setString(1, node.getName());
                rs = ps.executeQuery();
                if (!rs.next()) {
                	PasswordDAO pDAO = PasswordDAO.getInstance();
                    Password password = pDAO.getById(deletingUser, node.getName());
                    if (password != null) {
                    	pDAO.delete(deletingUser, password);
                    }
                }

            } finally {
                DatabaseConnectionUtils.close(rs);
                DatabaseConnectionUtils.close(ps);
            }
        }
    }

    /**
     * Gets the list of nodes which are the parentage of a node in order
     * (i.e. first is top level, ..., last-1 is nodes parent, last is node).
     *
     * @param node The node to get the parentage of.
     *
     * @return a List of the nodes ancestors.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     */

    public List<HierarchyNode> getParentage(final HierarchyNode node)
        throws SQLException {
        final List<HierarchyNode> parentage = new ArrayList<HierarchyNode>();
        String currentNodeId = node.getParentId();
        while (currentNodeId != null ) {
            HierarchyNode thisNode = getById(currentNodeId);
            parentage.add(0, thisNode);
            currentNodeId = thisNode.getParentId();
        }

        return parentage;
    }

    /**
     * Gets the a string representation of the parentage of a node.
     *
     * @param node The node to get the parentage of.
     *
     * @return A String representation of the parentage.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     */

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

    /**
     * Gets the summary for a node.
     *
     * @param node The node to get the summary of.
     */

    public HierarchyNodeSummary getSummary( final HierarchyNode node )
    	throws SQLException {
    	String nodeId = node.getNodeId();

    	HierarchyNodeSummary summary = summaryCache.get(nodeId);
    	if( summary == null ) {
    		summary = new HierarchyNodeSummary(nodeId, getParentageAsText(node));
    		summaryCache.put(nodeId, summary);
    	}
    	return summary;
    }

    /**
     * Get the summary for a node given its' ID.
     *
     * @param nodeId The node to get the summary of.
     */

    public HierarchyNodeSummary getSummary( final String nodeId )
            throws SQLException {
        return getSummary(getById(nodeId));
    }

    /**
     * Gets the Node ID for a specific object.
     *
     * @param testParentId The ID of the parent for the object node.
     * @param id The ID of the object.
     *
     * @return The ID of the first matching node.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     */

    public String getNodeIDForObject(final String testParentId, final String id)
        throws SQLException {
        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_NODE_ID_FOR_CHILD_OBJECT_ID_SQL);
        try {
            ps.setString(1, testParentId);
            ps.setString(2, id);
            ps.setMaxRows(1);

            ResultSet rs = ps.executeQuery();
            try {
	            if (rs.next()) {
	                return rs.getString(1);
	            }

	            return null;
            } finally {
                DatabaseConnectionUtils.close(rs);
            }
        } finally {
            DatabaseConnectionUtils.close(ps);
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
        	final HierarchyNode thisParent = getById(currentParentId);
        	final String thisParentId = thisParent.getNodeId();
        	if( thisParentId.equals(parentId)) {
        		return true;
        	}
        	currentParentId = thisParentId;
        }

        return false;
    }

    /**
     * Gets all of the Password children of a given node.
     *
     * @param node The node to get the Passwords under.
     * @param user The user requesting the information.

     * @return A Set of Passwords which exist under the specified node.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem decrypting the data.
     * @throws UnsupportedEncodingException
     */

    public Set<Password> getAllChildrenObjects(final HierarchyNode node, final User user, final Comparator<Password> comparator)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        Map<String, Password> resultMap = new HashMap<>();

        addUserAccessControlAccessibleObjects(node, user, resultMap);
        addGroupAccessControlAccessibleObjects(node, user, resultMap);

        Set<Password> results = comparator == null ? new TreeSet<Password>() : new TreeSet<Password>(comparator);

        results.addAll(resultMap.values());
        return results;
    }

    private void addUserAccessControlAccessibleObjects(final HierarchyNode node, final User user,
                                                       Map<String,Password> results)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        StringBuffer sql = new StringBuffer(GET_CHILD_OBJECTS_VIA_UAC_SQL);
        if( ! user.isAdministrator() && ! user.isSubadministrator() ) {
            sql.append("   AND (pass.enabled is null OR pass.enabled = 'Y')" );
        }

        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(sql.toString());
        ResultSet rs = null;
        try {
            ps.setString(1, node.getNodeId());
            ps.setString(2, user.getUserId());

            rs = ps.executeQuery();
            while (rs.next()) {
                String passwordId = rs.getString(UserAccessControlDAO.UAC_FIELD_COUNT+1);
                if(results.containsKey(passwordId)) {
                    continue;
                }

                UserAccessControl ac = new UserAccessControl(rs, 1, user);
                try {
                    Password password = new Password(passwordId, rs.getBytes(UserAccessControlDAO.UAC_FIELD_COUNT + 2), ac);
                    results.put(passwordId, password);
                } catch(IOException e) {
                    Logger.getAnonymousLogger().log(Level.SEVERE, "Unable to decrypt password "+passwordId, e);
                }
            }
        } finally {
            DatabaseConnectionUtils.close(rs);
            DatabaseConnectionUtils.close(ps);
        }
    }

    private void addGroupAccessControlAccessibleObjects(final HierarchyNode node, final User user,
                                                        Map<String,Password> results)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        StringBuffer sql = new StringBuffer(GET_CHILD_OBJECTS_VIA_GAC_SQL);
        if( ! user.isAdministrator() && ! user.isSubadministrator() ) {
            sql.append("   AND (pass.enabled is null OR pass.enabled = 'Y')" );
        }

        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(sql.toString());
        ResultSet rs = null;
        try {
            ps.setString(1, node.getNodeId());
            ps.setString(2, user.getUserId());

            GroupDAO gDAO = GroupDAO.getInstance();
            rs = ps.executeQuery();
            while (rs.next()) {
                String passwordId = rs.getString(GroupAccessControlDAO.GAC_FIELD_COUNT+1);
                if(results.containsKey(passwordId)) {
                    continue;
                }

                Group group = gDAO.getByIdDecrypted(rs.getString(4), user);
                GroupAccessControl ac = new GroupAccessControl(rs, 1, group);
                try {
                    Password password = new Password(passwordId, rs.getBytes(GroupAccessControlDAO.GAC_FIELD_COUNT + 2), ac);
                    results.put(passwordId, password);
                } catch(IOException e) {
                    Logger.getAnonymousLogger().log(Level.SEVERE, "Unable to decrypt password "+passwordId, e);
                }
            }
        } finally {
            DatabaseConnectionUtils.close(rs);
            DatabaseConnectionUtils.close(ps);
        }
    }

    public Set<HierarchyNode> getChildrenContainerNodesForUser(final HierarchyNode node,
            final User theUser, boolean includeEmpty, final Comparator<HierarchyNode> comparator)
        throws SQLException, GeneralSecurityException {
        Set<HierarchyNode> nodeSet;
        if(comparator == null) {
        	nodeSet = new TreeSet<HierarchyNode>();
        } else {
        	nodeSet = new TreeSet<HierarchyNode>(comparator);
        }
        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_CHILDREN_NODES_SQL);
        try {
            ps.setString(1, node.getNodeId());
            ResultSet rs = ps.executeQuery();
            try {
	            if( theUser.isAdministrator() ) {
                    while (rs.next()) {
                        nodeSet.add(new HierarchyNode(rs, 1));
                    }
                    return nodeSet;
                }

                HierarchyNodeAccessRuleDAO hnarDAO = HierarchyNodeAccessRuleDAO.getInstance();

                if( includeEmpty ) {
                    while (rs.next()) {
                        String nodeId = rs.getString(1);
                        if (hnarDAO.getAccessibilityForUser(nodeId, theUser, false)
                                != HierarchyNodeAccessRuleDAO.ACCESIBILITY_DENIED) {
                            nodeSet.add(new HierarchyNode(rs, 1));
                        }
                    }
                    return nodeSet;
                }

                while (rs.next()) {
                    String nodeId = rs.getString(1);
                    if( hnarDAO.getAccessibilityForUser(nodeId, theUser, false)
                                            != HierarchyNodeAccessRuleDAO.ACCESIBILITY_DENIED) {
                        if( hasChildrenValidForUser(nodeId, theUser) ) {
                            nodeSet.add(new HierarchyNode(rs, 1));
                        }
                    }
                }

	        	return nodeSet;
            } finally {
                DatabaseConnectionUtils.close(rs);
            }
        } finally {
        	DatabaseConnectionUtils.close(ps);
        }
    }

    /**
     * Gets the children of specific node which are valid for a given user.
     *
     * @param node The node to get the children of.
     * @param theUser The user for which the nodes must be valid.
     * @param includeEmpty Whether or not to include folders which have no user
     *  accessible content (true = include them).
     *
     * @return The requested node, or null if it doesn't exist.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem decrypting the data.
     * @throws UnsupportedEncodingException
     */

    public HierarchyNodeChildren getChildrenValidForUser(final HierarchyNode node, final User theUser,
    		boolean includeEmpty, final Comparator<HierarchyNode> nodeComparator, final Comparator<Password> objectComparator)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        Set<HierarchyNode> containers = getChildrenContainerNodesForUser(node, theUser, includeEmpty, nodeComparator);
        Set<Password> objects = getAllChildrenObjects(node, theUser, objectComparator);

        return new HierarchyNodeChildren(containers, objects);
    }

    private boolean hasChildrenObjectNodesViaUac(final String nodeId, final User theUser)
            throws SQLException {
        return exists(GET_VALID_CHILD_OBJECT_IDS_VIA_UAC_SQL, nodeId, theUser.getUserId());
    }

    private boolean hasChildrenObjectNodesViaGac(final String nodeId, final User theUser)
            throws SQLException {
        return exists(GET_VALID_CHILD_OBJECT_IDS_VIA_GAC_SQL, nodeId, theUser.getUserId());
    }

    /**
     * Tests to see if there are subnodes which the user can access which hold entries.
     *
     * @param nodeId The ID of the node to test.
     * @param theUser The user form whom the check should be performed.
     *
     * @return true if there are nodes with data in, false if not.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem decrypting the data.
     */

    private boolean hasChildrenNodes(final String nodeId, final User theUser)
            throws GeneralSecurityException, SQLException {
        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_CHILDREN_NODE_IDS_SQL);
        try {
            ps.setString(1, nodeId);

            ResultSet rs = ps.executeQuery();
            try {
	            if (!rs.next()) {
	            	return false;
	            }

                if (theUser.isAdministrator() || theUser.isSubadministrator()) {
                    return true;
                }

                do {
                    if (hasChildrenValidForUser(rs.getString(1), theUser)) {
                        return true;
                    }
                } while (rs.next());

                return false;
            } finally {
                DatabaseConnectionUtils.close(rs);
            }
        } finally {
            DatabaseConnectionUtils.close(ps);
        }
    }

    public HierarchyNode getPersonalNodeForUser(final User user)
            throws  SQLException {
        return fetchObjectIfExists(GET_USER_CONTAINER_NODE_SQL, user.getUserId());
    }

    /**
     * Tests if a node has children which a user can access.
     *
     * @param nodeId The ID of the HierarchyNode to check.
     * @param theUser The user to check access for.
     *
     * @return true if this node contains user accessible data, false if not.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem decrypting the data.
     */

    private boolean hasChildrenValidForUser(final String nodeId, final User theUser)
            throws SQLException, GeneralSecurityException {
        return hasChildrenObjectNodesViaUac(nodeId, theUser)
                || hasChildrenObjectNodesViaGac(nodeId, theUser)
                || hasChildrenNodes(nodeId, theUser);
    }

    /**
     * Get all children of a node.
     *
     * @param node The node to get the children of.
     *
     * @return A List of child nodes.
     *
     * @throws SQLException If there is a problem accessing the database.
     */

    public List<HierarchyNode> getAllChildren(final HierarchyNode node)
        throws SQLException {
        return getMultiple(GET_ALL_CHILDREN_NODES_SQL, node.getNodeId());
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
        store(node);
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
        store(newNode);

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
        HierarchyNode newParent = getById(newParentId);
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

        for(HierarchyNode thisNode : getAllChildren(node)) {
            deepCopyToWork(thisNode, newParent);
        }
    }

    /**
     * Perform an action on all the objects in this node, and optional recurse
     * into the child nodes..
     *
     * @param node The start point for performing the action.
     * @param theUser The user to search for.
     * @param action The action to perform.
     */

    public void processObjectNodes( final HierarchyNode node, final User theUser,
            final NodeObjectAction action, final boolean recurse)
        throws Exception {
        if(recurse) {
        	for( HierarchyNode thisNode : getChildrenContainerNodesForUser(node, theUser, true, null)) {
                processObjectNodes(thisNode, theUser, action, true);
            }
        }

        for(AccessControledObject aco: getAllChildrenObjects(node, theUser, null)) {
            action.process(node, aco);
        }
    }

    /**
     * Gets the default password permissions for a hierarchy node.
     *
     * @param nodeId The ID of the node
     * @param userPermMap The map of user permissions.
     * @param groupPermMap The map of group permissions.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem accessing the data.
     * @throws UnsupportedEncodingException
     */

    public void getDefaultPermissionsForNode(final String nodeId,
    		final Map<String, String> userPermMap, final Map<String, String> groupPermMap)
        throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
    	if( nodeId == null )
    		return;

        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_DEFAULT_PASSWORD_PERMISSIONS_FOR_NODE);
        try {
            ps.setString(1, nodeId);

            ResultSet rs = ps.executeQuery();
            try {
	            while (rs.next()) {
	            	String type = rs.getString(1);
	            	String actorId = rs.getString(2);
	            	String permission = rs.getString(3);
	            	if			( type.equals("g") ) {
	            		groupPermMap.put(actorId, permission);
	            	} else if	( type.equals("u") ) {
	            		userPermMap.put(actorId, permission);
	            	} else {
	            		throw new GeneralSecurityException("Unknown password permission default "+type);
	            	}
	            }
            } finally {
                DatabaseConnectionUtils.close(rs);
            }
        } finally {
            DatabaseConnectionUtils.close(ps);
        }
    }

    /**
     * Get the default permissions for a user for a node.
     *
     * @param user The user to get the permissions for.
     * @param nodeId The ID of the node to get the permissions for.
     *
     * @return The default permission for the user.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     */

    public UserNodeDefaultPermission getDefaultPermissionForUser(final UserSummary user, String nodeId)
        throws SQLException {
    	synchronized( this ) {
	        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_PERMISSION_SUMMARY_FOR_USER);
	        try {
	            ps.setString(1, user.getId());
	            ps.setString(2, nodeId);
	            ps.setMaxRows(1);

	            ResultSet rs = ps.executeQuery();
	            try {
		            if(rs.next()) {
			           return new UserNodeDefaultPermission(user, rs.getString(1));
		            }

		           return new UserNodeDefaultPermission(user, "0");
		        } finally {
		            DatabaseConnectionUtils.close(rs);
	            }
	        } finally {
	            DatabaseConnectionUtils.close(ps);
	        }
    	}
    }

    /**
     * Get the permission summary for a specific group
     *
     * @param group The group to get the permission summary for
     * @return The permission summary.
     *
     * @throws SQLException
     *             Thrown if there is a problem accessing the database.
     */

    public GroupNodeDefaultPermission getDefaultPermissionForGroup(final GroupSummary group, String nodeId)
        throws SQLException {
    	synchronized( this ) {
	        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_PERMISSION_SUMMARY_FOR_GROUP);
	        try {
	            ps.setString(1, group.getId());
	            ps.setString(2, nodeId);
	            ps.setMaxRows(1);

	            ResultSet rs = ps.executeQuery();
	            try {
		            if(rs.next()) {
			           return new GroupNodeDefaultPermission(group, rs.getString(1));
		            }

		           return new GroupNodeDefaultPermission(group, "0");
		        } finally {
		            DatabaseConnectionUtils.close(rs);
	            }
	        } finally {
	            DatabaseConnectionUtils.close(ps);
	        }
    	}
    }

    /**
     * Gets the default password permissions for a hierarhcy node.
     *
     * @param nodeId The ID of the node
     * @param userPermMap The map of user permissions.
     * @param groupPermMap The map of group permissions.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem accessing the data.
     * @throws UnsupportedEncodingException
     */

    public void getDefaultPermissionsForNodeIncludingInherited(final String nodeId,
    		final Map<String,String> userPermMap, final Map<String,String> groupPermMap)
        throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
    	if( nodeId == null )
    		return;

        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_DEFAULT_PASSWORD_PERMISSIONS_FOR_NODE);
        try {
        	String currentNodeId =  nodeId;
        	while( currentNodeId != null ) {
            	HierarchyNode currentNode =  getById(currentNodeId);
	            ps.setString(1, currentNodeId);

	            ResultSet rs = ps.executeQuery();
	            try {
	                while (rs.next()) {
	                	int idx = 1;
	                	String type = rs.getString(idx++);
	                	String actorId = rs.getString(idx++);
	                	String permission = rs.getString(idx);
	                	if			( type.equals("g") ) {
	                		String oldValue = groupPermMap.get(actorId);
	                		if( oldValue == null && !permission.equals("0")) {
	                			groupPermMap.put(actorId, permission);
	                		}
	                	} else if	( type.equals("u") ) {
	                		String oldValue = userPermMap.get(actorId);
	                		if( oldValue == null && !permission.equals("0")) {
	                			userPermMap.put(actorId, permission);
	                		}
	                	} else {
	                		throw new GeneralSecurityException("Unknown password permission default "+type);
	                	}
	                }
	            } finally {
	                DatabaseConnectionUtils.close(rs);

	            }

	            currentNodeId = currentNode.getParentId();
            }
        } finally {
            DatabaseConnectionUtils.close(ps);
        }
    }

    /**
     * Sets the default password permissions for a hierarchy node.
     *
     * @param nodeId The ID of the node
     * @param userPermMap The map of user permissions.
     * @param groupPermMap The map of group permissions.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     */

    public void setDefaultPermissionsForNode(final String nodeId,
    		final Map<String,String> userPermMap, final Map<String,String> groupPermMap)
        throws SQLException {
        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(DELETE_PASSWORD_DEFAULTS_FOR_NODE);
        try {
            ps.setString(1, nodeId);
            ps.executeUpdate();
        } finally {
            DatabaseConnectionUtils.close(ps);
        }

        ps = BOMFactory.getCurrentConntection().prepareStatement(SET_PASSWORD_DEFAULTS_FOR_NODE);
        try {
	        ps.setString(1, nodeId);
	        ps.setString(2, "u");
	        setDefaultPermissions(ps, userPermMap);
	        ps.setString(2, "g");
	        setDefaultPermissions(ps, groupPermMap);
        } finally {
            DatabaseConnectionUtils.close(ps);
        }
    }

    /**
     * Sets the default password permissions of a specific type for a hierarhcy node.
     *
     * @param ps The prepared statement used to add the data.
     * @param map The map of permissions to add.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     */

    private void setDefaultPermissions( PreparedStatement ps, Map<String,String> map)
   		throws SQLException {
    	int addCounter = 0;

    	for(Map.Entry<String, String> thisEntry : map.entrySet()) {
    		ps.setString(3, thisEntry.getKey());
    		ps.setString(4, thisEntry.getValue());
    		ps.addBatch();

    		addCounter++;
    		if( addCounter == 100 ) {
    			ps.executeBatch();
    			addCounter = 0;
    		}
    	}
    	if( addCounter != 0 ) {
    		ps.executeBatch();
    	}
    }

    /**
     * Gets the combined permissions for a node inheriting all the permissions from
     * super nodes.
     *
     * @param nodeId The ID of the node
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem accessing the data.
     * @throws UnsupportedEncodingException
     */

    public void getCombinedDefaultPermissionsForNode(final String nodeId,
    		final Map<String, String> userPermMap, final Map<String, String> groupPermMap)
        throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
    	if( nodeId != null ) {
    		HierarchyNode thisNode = getById(nodeId);
    		getCombinedDefaultPermissionsForNode(thisNode.getParentId(), userPermMap, groupPermMap);
    	}

    	getDefaultPermissionsForNode(nodeId, userPermMap, groupPermMap);
    }

    /**
     * Check to see if a node with the specified name is a personal node or not.
     *
     * @param name The name of the node to check.
     * @return true if the node is a personal node, false if not.
     */

    public boolean isPersonalByName(final String name) throws SQLException {
    	return isPersonalById( getByName(name).getNodeId() );
    }

    /**
     * Check to see if a node with the specified id is a personal node or not.
     *
     * @param id The id of the node to check.
     * @return true if the node is a personal node, false if not.
     * @throws SQLException
     */

    public boolean isPersonalById(final String id) throws SQLException {
    	synchronized(this) {
	    	if( personalNodeCache == null ) {
	    		personalNodeCache = new Cache<String,Boolean>();
	    	}
	    	Boolean cachedValue = personalNodeCache.get(id);
	    	if(cachedValue != null) {
	    		return cachedValue;
	    	}
    	}

    	HierarchyNode node = getById(id);
    	boolean result;
    	if( node.getParentId() != null ) {
    		result = isPersonalById(node.getParentId());
    	} else {
    		result = (!node.getNodeId().equals(HierarchyNode.ROOT_NODE_ID));
    	}
    	personalNodeCache.put(id, result);

    	return result;
    }

    /**
     * Class holding the details of the default permissions a user has for a node
     */

    public static class UserNodeDefaultPermission
        implements JavaBean {
    	private final UserSummary user;
    	private final String permission;


    	public UserNodeDefaultPermission(final UserSummary user, final String permission) {
    		this.user = user;
    		this.permission = permission;
    	}


		public UserSummary getUser() {
			return user;
		}
		public String getPermission() {
			return permission;
		}
    }


    /**
     * Class holding the details of the default permissions a group has for a node
     */

    public static class GroupNodeDefaultPermission
        implements JavaBean {
    	private final GroupSummary group;
    	private final String permission;


    	public GroupNodeDefaultPermission(final GroupSummary group, final String permission) {
    		this.group = group;
    		this.permission = permission;
    	}


		public GroupSummary getGroup() {
			return group;
		}
		public String getPermission() {
			return permission;
		}
    }

    //------------------------


    private static final class InstanceHolder {
    	private static final HierarchyNodeDAO INSTANCE = new HierarchyNodeDAO();
    }

    public static HierarchyNodeDAO getInstance() {
    	return InstanceHolder.INSTANCE;
    }
}
