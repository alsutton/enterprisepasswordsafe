package com.enterprisepasswordsafe.engine.database;

import com.enterprisepasswordsafe.engine.database.derived.UserSummary;
import com.enterprisepasswordsafe.engine.nodes.GroupNodeDefaultPermission;
import com.enterprisepasswordsafe.engine.nodes.UserNodeDefaultPermission;
import com.enterprisepasswordsafe.engine.utils.DatabaseConnectionUtils;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Map;

public class HierarchyNodePermissionDAO
    extends JDBCBase {

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
     * The SQL to get the user summary for a search
     */

    private static final String GET_PERMISSION_SUMMARY_FOR_USER =
            "SELECT   hpd.permission FROM hierarchy_password_defaults hpd"
         + " WHERE hpd.actor_id = ? AND hpd.node_id = ? AND hpd.type = 'u'";

    /**
     * The SQL to get the user summary for a search
     */

    private static final String GET_PERMISSION_SUMMARY_FOR_GROUP =
            "SELECT hpd.permission FROM hierarchy_password_defaults hpd"
            + " WHERE hpd.actor_id = ? AND hpd.node_id = ? AND hpd.type = 'g'";

    private HierarchyNodeDAO hierarchyNodeDAO;

    public HierarchyNodePermissionDAO() {
        hierarchyNodeDAO = HierarchyNodeDAO.getInstance();
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

    public GroupNodeDefaultPermission getDefaultPermissionForGroup(final Group group, String nodeId)
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
                HierarchyNode currentNode =  hierarchyNodeDAO.getById(currentNodeId);
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
        runResultlessParameterisedSQL(DELETE_PASSWORD_DEFAULTS_FOR_NODE, nodeId);

        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(SET_PASSWORD_DEFAULTS_FOR_NODE);
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
            HierarchyNode thisNode = hierarchyNodeDAO.getById(nodeId);
            getCombinedDefaultPermissionsForNode(thisNode.getParentId(), userPermMap, groupPermMap);
        }

        getDefaultPermissionsForNode(nodeId, userPermMap, groupPermMap);
    }
}
