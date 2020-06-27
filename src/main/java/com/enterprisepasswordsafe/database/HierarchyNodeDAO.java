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

import com.enterprisepasswordsafe.database.derived.HierarchyNodeSummary;
import com.enterprisepasswordsafe.engine.accesscontrol.AccessControl;
import com.enterprisepasswordsafe.engine.users.UserClassifier;
import com.enterprisepasswordsafe.engine.utils.Cache;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Data access object for nodes in the hierarchy.
 */
public final class HierarchyNodeDAO
    extends StoredObjectManipulator<HierarchyNode> {

	/**
     * The shared root node.
     */

    private static final HierarchyNode ROOT_NODE = new HierarchyNode();

    private static final String NODE_FIELDS = "node_id, name, parent_id, type";

    /**
     * SQL to get the parent ID of a node from its ID.
     */

    private static final String GET_NODE_PARENT_ID_SQL = "SELECT " + NODE_FIELDS + " FROM hierarchy WHERE node_id = ? ";

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
            "SELECT node_id FROM hierarchy WHERE parent_id = ? AND name = ? AND type = " + HierarchyNode.OBJECT_NODE;

    /**
     * The SQL statement to get the valid object node children for a given
     * user where the user has user access control access.
     */

    private static final String GET_VALID_CHILD_OBJECT_IDS_VIA_UAC_SQL =
            "SELECT   h.name FROM hierarchy h, user_access_control uac "
            + " WHERE h.parent_id = ? AND h.type = " + HierarchyNode.OBJECT_NODE + " AND uac.item_id = h.name "
            + "  AND uac.rkey is not null AND uac.user_id = ? ";

    /**
     * The SQL statement to get the valid object node children for a given
     * user where the user has user access control access.
     */

    private static final String GET_VALID_CHILD_OBJECT_IDS_VIA_GAC_SQL =
            "SELECT   h.name "
            + "  FROM hierarchy h, group_access_control gac, membership m, groups g "
            + " WHERE h.parent_id = ? AND h.type = "+ HierarchyNode.OBJECT_NODE+ " AND gac.item_id = h.name "
            + "   AND gac.rkey is not null AND m.group_id = gac.group_id AND m.user_id = ? "
            + "   AND g.group_id = gac.group_id AND g.status = " + Group.STATUS_ENABLED;

    /**
     * The SQL statement to get the all child object node ids.
     */

    private static final String GET_CHILD_OBJECTS_VIA_UAC_SQL =
            "SELECT   " + UserAccessControlDAO.UAC_FIELDS+", "+PasswordDAO.PASSWORD_FIELDS
            + "  FROM hierarchy h, passwords pass, user_access_control uac "
            + " WHERE h.parent_id = ? AND h.type = " + HierarchyNode.OBJECT_NODE + " AND uac.item_id = h.name "
            + "  AND uac.rkey is not null AND uac.user_id = ? AND pass.password_id = h.name";

    /**
     * The SQL statement to get the valid object node children for a given
     * user where the user has user access control access.
     */

    private static final String GET_CHILD_OBJECTS_VIA_GAC_SQL =
            "SELECT   " + GroupAccessControlDAO.GAC_FIELDS +", "+PasswordDAO.PASSWORD_FIELDS
            + "  FROM hierarchy h, passwords pass, group_access_control gac, membership m, groups g "
            + " WHERE h.parent_id = ? AND h.type = "+ HierarchyNode.OBJECT_NODE+ " AND pass.password_id = h.name"
            + "   AND gac.item_id = h.name AND gac.rkey is not null AND m.group_id = gac.group_id "
            + "   AND m.user_id = ? AND g.group_id = gac.group_id AND g.status = " + Group.STATUS_ENABLED;


    /**
     * The SQL statement to get the child container nodes of a specific node.
     */

    private static final String GET_CHILD_CONTAINER_NODES_SQL =
            "SELECT " + NODE_FIELDS + "  FROM hierarchy WHERE parent_id = ? AND type=" + HierarchyNode.CONTAINER_NODE;

    /**
     * The SQL statement to get the child container nodes of a specific node.
     */

    private static final String GET_CHILDREN_NODE_IDS_SQL =
            "SELECT   node_id FROM hierarchy WHERE parent_id = ? AND type=" + HierarchyNode.CONTAINER_NODE;

    /**
     * The SQL statement to get the user node for a user
     */

    private static final String GET_USER_CONTAINER_NODE_SQL =
            "SELECT   node_id, name, parent_id, type FROM hierarchy WHERE name = ? "
            + "   AND type = " + HierarchyNode.USER_CONTAINER_NODE;

    /**
     * The SQL statement to get the child container nodes of a specific node.
     */

    private static final String GET_CHILD_BY_NAME_SQL =
            "SELECT node_id FROM hierarchy WHERE parent_id = ? AND name = ?";

    /**
     * The SQL statement to write a new node to the database.
     */

    private static final String INSERT_NODE_SQL =
            "INSERT INTO hierarchy( name, parent_id, type, node_id ) VALUES ( ?, ?, ?, ? ) ";

    /**
     * The SQL statement to update a node in the hierarchy.
     */

    private static final String UPDATE_NODE_SQL =
            "UPDATE hierarchy SET name = ?, parent_id = ?, type = ? WHERE node_id = ?";

    /**
     * SQL to count the number of nodes referring to a object.
     */

    private static final String TEST_NODES_REFERRING_TO_OBJECT_NODE_SQL =
            "SELECT " + NODE_FIELDS + " FROM hierarchy WHERE name = ? AND type = " + HierarchyNode.OBJECT_NODE;

    /**
     * The SQL to delete a node.
     */

    private static final String DELETE_SQL = "DELETE FROM hierarchy WHERE node_id = ?";

    /**
     * Cache for node summaries.
     */

    private final Cache<String,HierarchyNodeSummary> summaryCache = new Cache<String,HierarchyNodeSummary>();

	private final UserClassifier userClassifier = new UserClassifier();

	/**
	 * Private constructor to prevent instantiation
	 */

	private HierarchyNodeDAO( ) {
		super(GET_NODE_BY_ID_SQL, GET_NODE_BY_NAME_SQL, DELETE_SQL);
	}

    @Override
    HierarchyNode newInstance(ResultSet rs)
            throws SQLException {
        return new HierarchyNode(rs, 1);
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
        String statementSQL = getById(node.getNodeId()) == null ? INSERT_NODE_SQL : UPDATE_NODE_SQL;
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(statementSQL)) {
            ps.setString(1, node.getName());
            ps.setString(2, node.getParentId());
            ps.setInt   (3, node.getType());
            ps.setString(4, node.getNodeId());
            ps.executeUpdate();
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

        HierarchyNode node = fetchObjectIfExists(GET_NODE_PARENT_ID_SQL, nodeId);
        return node == null ? null : node.getNodeId();
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
        return fetchObjectIfExists(GET_CHILD_BY_NAME_SQL, parentId, name) != null;
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
            throws SQLException, GeneralSecurityException, IOException {
        if (node.getType() == HierarchyNode.CONTAINER_NODE) {
            deleteAllChildren(node, deletingUser);
        }

        runResultlessParameterisedSQL(DELETE_SQL, node.getNodeId());

        if (node.getType()== HierarchyNode.OBJECT_NODE) {
            deleteOrphanedPasswords(node, deletingUser);
        }
    }

    private void deleteAllChildren(HierarchyNode node, User deletingUser)
            throws SQLException, GeneralSecurityException, IOException {
        for(HierarchyNode thisNode : getMultiple(GET_ALL_CHILDREN_NODES_SQL, node.getNodeId())) {
            deleteNode(thisNode, deletingUser);
        }

        TamperproofEventLogDAO.getInstance().create(TamperproofEventLog.LOG_LEVEL_HIERARCHY_MANIPULATION,
                deletingUser, null, "Deleted Node " + node.getName() +
                        " from {node:"+ node.getNodeId()+ "}",true);
    }

    private void deleteOrphanedPasswords(HierarchyNode node, User deletingUser)
            throws SQLException, IOException, GeneralSecurityException {
        HierarchyNode referringNode = fetchObjectIfExists(TEST_NODES_REFERRING_TO_OBJECT_NODE_SQL, node.getName());
        if (referringNode == null) {
            PasswordDAO pDAO = PasswordDAO.getInstance();
            Password password = pDAO.getById(deletingUser, node.getName());
            if (password != null) {
                pDAO.delete(deletingUser, password);
            }
        }
    }

    public String getNodeIDForObject(final String testParentId, final String id)
        throws SQLException {
        HierarchyNode node = fetchObjectIfExists(GET_NODE_ID_FOR_CHILD_OBJECT_ID_SQL, testParentId, id);
        return node == null ? null : node.getNodeId();
    }

    public Set<Password> getAllChildrenObjects(final HierarchyNode node, final User user, final Comparator<Password> comparator)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        Map<String, Password> resultMap = new HashMap<>();

        addUserAccessControlAccessibleObjects(node, user, resultMap);
        addGroupAccessControlAccessibleObjects(node, user, resultMap);

        Set<Password> results = comparator == null ? new TreeSet<>() : new TreeSet<>(comparator);

        results.addAll(resultMap.values());
        return results;
    }

    private void addUserAccessControlAccessibleObjects(final HierarchyNode node, final User user,
                                                       Map<String,Password> results)
            throws SQLException, GeneralSecurityException {
        StringBuilder sql = new StringBuilder(GET_CHILD_OBJECTS_VIA_UAC_SQL);
        if(!userClassifier.isPriviledgedUser(user)) {
            sql.append("   AND (pass.enabled is null OR pass.enabled = 'Y')" );
        }

        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(sql.toString())) {
            ps.setString(1, node.getNodeId());
            ps.setString(2, user.getId());

            try(ResultSet rs = ps.executeQuery()) {
                processObjectResults(user, results, rs);
            }
        }
    }

    private void processObjectResults(User user, Map<String, Password> results, ResultSet rs)
            throws SQLException, GeneralSecurityException {
        while (rs.next()) {
            String passwordId = rs.getString(AbstractAccessControlDAO.ACCESS_CONTROL_FIELD_COUNT + 1);
            if (results.containsKey(passwordId)) {
                continue;
            }

            addPasswordToResults(results, passwordId, rs,UserAccessControlDAO.buildFromResultSet(rs, user));
        }
    }


    private void addGroupAccessControlAccessibleObjects(final HierarchyNode node, final User user,
                                                        Map<String,Password> results)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        StringBuilder sql = new StringBuilder(GET_CHILD_OBJECTS_VIA_GAC_SQL);
        if(!userClassifier.isPriviledgedUser(user)) {
            sql.append("   AND (pass.enabled is null OR pass.enabled = 'Y')" );
        }

        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(sql.toString())) {
            ps.setString(1, node.getNodeId());
            ps.setString(2, user.getId());

            try(ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    processGroupAccessControlResult(results, user, rs);
                }
            }
        }
    }

    private void processGroupAccessControlResult(Map<String,Password> results, User user, ResultSet rs)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        String passwordId = rs.getString(AbstractAccessControlDAO.ACCESS_CONTROL_FIELD_COUNT + 1);
        if (results.containsKey(passwordId)) {
            return;
        }

        Group group =  GroupDAO.getInstance().getByIdDecrypted(rs.getString(4), user);
        addPasswordToResults(results, passwordId, rs, GroupAccessControlDAO.buildFromResultSet(rs, group));
    }

    private void addPasswordToResults(Map<String,Password> results, String passwordId,
                                      ResultSet rs, AccessControl ac)
            throws SQLException, GeneralSecurityException {
        try {
            Password password = new Password(passwordId, rs.getBytes(AbstractAccessControlDAO.ACCESS_CONTROL_FIELD_COUNT + 2), ac);
            results.put(passwordId, password);
        } catch (IOException e) {
            Logger.getAnonymousLogger().log(Level.SEVERE, "Unable to decrypt password " + passwordId, e);
        }
    }

    public Collection<HierarchyNode> getChildrenContainerNodesForUser(final HierarchyNode node,
            final User theUser, boolean includeEmpty, final Comparator<HierarchyNode> comparator)
        throws SQLException, GeneralSecurityException {
        List<HierarchyNode> children = getMultiple(GET_CHILD_CONTAINER_NODES_SQL, node.getNodeId());
        if( userClassifier.isAdministrator(theUser)) {
            return children;
        }

        children.removeAll(getNodesBlockedForUser(theUser, includeEmpty, children));

        if (comparator != null) {
            children.sort(comparator);
        }

        return children;
    }

    private List<HierarchyNode> getNodesBlockedForUser(User theUser, boolean includeEmpty, List<HierarchyNode> children)
            throws GeneralSecurityException, SQLException {
        HierarchyNodeAccessRuleDAO hnarDAO = HierarchyNodeAccessRuleDAO.getInstance();
        List<HierarchyNode> blockedNodes= new ArrayList<>();
        for(HierarchyNode thisNode : children) {
            if (hnarDAO.getAccessibilityForUser(thisNode.getNodeId(), theUser, false) == HierarchyNodeAccessRuleDAO.ACCESIBILITY_DENIED
            ||  (!includeEmpty && !hasChildrenValidForUser(thisNode.getNodeId(), theUser) )) {
                blockedNodes.add(thisNode);
            }
        }
        return blockedNodes;
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
        List<String> childNodeIds = getFieldValues(GET_CHILDREN_NODE_IDS_SQL, nodeId);
        if(childNodeIds.isEmpty()) {
            return false;
        }

        if (userClassifier.isPriviledgedUser(theUser)) {
            return true;
        }

        for(String childNodeId: childNodeIds) {
            if (hasChildrenValidForUser(childNodeId, theUser)) {
                return true;
            }
        }

        return false;
    }

    public HierarchyNode getPersonalNodeForUser(final User user)
            throws  SQLException {
        return fetchObjectIfExists(GET_USER_CONTAINER_NODE_SQL, user.getId());
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
        return exists(GET_VALID_CHILD_OBJECT_IDS_VIA_UAC_SQL, nodeId, theUser.getId())
            || exists(GET_VALID_CHILD_OBJECT_IDS_VIA_GAC_SQL, nodeId, theUser.getId())
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

    //------------------------


    private static final class InstanceHolder {
    	private static final HierarchyNodeDAO INSTANCE = new HierarchyNodeDAO();
    }

    public static HierarchyNodeDAO getInstance() {
    	return InstanceHolder.INSTANCE;
    }
}
