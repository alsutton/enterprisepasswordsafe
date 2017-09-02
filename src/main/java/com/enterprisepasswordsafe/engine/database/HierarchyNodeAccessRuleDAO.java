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

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import com.enterprisepasswordsafe.engine.database.derived.UserSummary;
import com.enterprisepasswordsafe.engine.utils.DatabaseConnectionUtils;
import com.enterprisepasswordsafe.proguard.ExternalInterface;

/**
 * Data access object for hierarchy node access rules.
 */

public abstract class HierarchyNodeAccessRuleDAO implements ExternalInterface {

    /**
     * The values for an accessibility rule.
     */

    public static final byte	ACCESIBILITY_DEFAULT = 0,
    							ACCESIBILITY_DENIED = 1,
    							ACCESIBILITY_ALLOWED = 2;

    /**
     * The values for an accessibility rule.
     */

    public static final Byte	ACCESIBILITY_DEFAULT_BYTE = Byte.valueOf((byte)0),
    							ACCESIBILITY_DENIED_BYTE = Byte.valueOf((byte)1),
    							ACCESIBILITY_ALLOWED_BYTE = Byte.valueOf((byte)2);
    /**
     * SQL to get the access rule for a node and user.
     */

    private static final String GET_USER_NODE_RULE_SQL =
            "SELECT setting "
        +   "  FROM hierarchy_access_control "
        +   " WHERE node_id = ? "
        +   "   AND user_id = ?";

    /**
     * SQL to get the access rule for a node and user.
     */

    private static final String GET_NODE_RULES_SQL =
            "SELECT hac.setting"
        +   "  FROM hierarchy_access_control hac"
        +   " WHERE node_id = ? "
        +   "   AND user_id = ? ";

    /**
     * SQL to insert an access rule for a node and user.
     */

    private static final String INSERT_USER_NODE_RULE_SQL =
           "INSERT INTO hierarchy_access_control(setting, node_id, user_id) "
        +   "                             VALUES(      ?,       ?,       ?) ";

    /**
     * SQL to update an access rule for a node and user.
     */

    private static final String UPDATE_USER_NODE_RULE_SQL =
           "UPDATE hierarchy_access_control "
        +  "   SET setting = ? "
        +  " WHERE node_id = ? "
        + "    AND user_id = ? ";

    /**
     * SQL to insert an access rule for a node and user.
     */

    private static final String DELETE_USER_NODE_RULE_SQL =
           "DELETE FROM hierarchy_access_control "
         + " WHERE node_id = ? "
         + "    AND user_id = ? ";

    /**
     * SQL to get the access rule for a node and user via the groups
     * the user is a member of.
     */

    private static final String GET_USERS_GROUP_NODE_RULES_SQL =
            "SELECT hgac.setting "
        +   "  FROM hierarchy_group_access_control hgac,"
        +	"       membership mem "
        +   " WHERE hgac.node_id = ? "
        +   "   AND hgac.group_id = mem.group_id "
        +	"	AND mem.user_id = ?";

    /**
     * SQL to get the access rule for a node and group.
     */

    private static final String GET_GROUP_NODE_RULE_SQL =
            "SELECT setting "
        +   "  FROM hierarchy_group_access_control "
        +   " WHERE node_id = ? "
        +   "   AND group_id = ? ";

    /**
     * SQL to insert an access rule for a node and user.
     */

    private static final String INSERT_GROUP_NODE_RULE_SQL =
           "INSERT INTO hierarchy_group_access_control(setting, node_id, group_id) "
        +   "                                    VALUES(     ?,       ?,       ?) ";

    /**
     * SQL to update an access rule for a node and user.
     */

    private static final String UPDATE_GROUP_NODE_RULE_SQL =
           "UPDATE hierarchy_group_access_control "
        +  "   SET setting = ? "
        +  " WHERE node_id = ? "
        + "    AND group_id = ? ";

    /**
     * SQL to insert an access rule for a node and user.
     */

    private static final String DELETE_GROUP_NODE_RULE_SQL =
           "DELETE FROM hierarchy_group_access_control "
         + " WHERE node_id = ? "
         + "   AND group_id = ? ";

    /**
     * Check if this node is usable by a specific user.
     *
     * @param conn The connection to the database.
     * @param user The user to get the rule for.
     *
     * @return true If the node is accessible by the user, false if not.
     */

    public byte getAccessibilityForUser( final HierarchyNode node, final User user)
        throws SQLException, GeneralSecurityException {
    	return getAccessibilityForUser( node.getNodeId(), user, true);
    }

    /**
     * Check if this node is usable by a specific user.
     *
     * @param conn The connection to the database.
     * @param user The user to get the rule for.
     *
     * @return true If the node is accessible by the user, false if not.
     */

    public byte getAccessibilityForUser( final String nodeId, final User user)
        throws SQLException, GeneralSecurityException {
        	return getAccessibilityForUser( nodeId, user, true);
	}

    /**
     * Check if this node is usable by a specific user.
     *
     * @param conn The connection to the database.
     * @param user The user to get the rule for.
     *
     * @return true If the node is accessible by the user, false if not.
     */

    public abstract byte getAccessibilityForUser( final String nodeId, final User user, boolean recurse)
        throws SQLException, GeneralSecurityException;

    /**
     * Check if this node is usable by a specific user.
     *
     * @param conn The connection to the database.
     * @param userId The ID of the user to get the rule for.
     *
     * @return true If the node is accessible by the user, false if not.
     */

    protected byte[] getUserAccessibilityRule( final String nodeId, final User user)
        throws SQLException {
        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_USER_NODE_RULE_SQL);
        try {
            ps.setString(1, nodeId);
            ps.setString(2, user.getUserId());

	        ResultSet rs = ps.executeQuery();
	        try {
	            if (rs.next()) {
	                return rs.getBytes(1);
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
     * Check if this node is usable by a specific user.
     *
     * @param conn The connection to the database.
     * @param userId The ID of the user to get the rule for.
     *
     * @return true If the node is accessible by the user, false if not.
     */

    protected List<byte[]> getUsersGroupAccessibilityRules( final String nodeId, final User user)
        throws SQLException {
        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_USERS_GROUP_NODE_RULES_SQL);
        try {
            ps.setString(1, nodeId);
            ps.setString(2, user.getUserId());

            ResultSet rs = ps.executeQuery();
            try {
	        	List<byte[]> ruleList = new ArrayList<byte[]>();
	            while(rs.next()) {
	                ruleList.add( rs.getBytes(1) );
	            }
	            return ruleList;
        	} finally {
        		DatabaseConnectionUtils.close(rs);
        	}
        } finally {
        	DatabaseConnectionUtils.close(ps);
        }
    }

    /**
     * Get the rule for the specified group accessing this node.
     *
     * @param conn The connection to the database.
     * @param groupdId The ID of the group to get the rule for.
     *
     * @return The accesibility rule.
     */

    protected byte[] getGroupAccessibilityRule( final HierarchyNode node,
            final String groupId)
        throws SQLException {

    	PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_GROUP_NODE_RULE_SQL);
        try {
            ps.setString(1, node.getNodeId());
            ps.setString(2,   groupId);

            ResultSet rs = ps.executeQuery();
            try {
	            if(rs.next()) {
	                return rs.getBytes(1);
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
     * Get all of the rules for this node.
     *
     * @param conn The connection to the database.
     * @param adminGroup The admin group to decrypt the users admin key.
     *
     * @return A Map of username to access rule.
     * @throws UnsupportedEncodingException
     */

    public Set<HierarchyNodeAccessRule> getAccessibilityRules( final HierarchyNode node,
            final Group adminGroup)
    throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
    	Set<HierarchyNodeAccessRule> permissions = new TreeSet<HierarchyNodeAccessRule>();

    	PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_NODE_RULES_SQL);
    	try {
	        ps.setString(1, node.getNodeId());

	        UserDAO uDAO = UserDAO.getInstance();
	    	for(UserSummary thisUser : uDAO.getSummaryListExcludingAdmin()) {
	            ResultSet rs = null;
	            try {
	            	ps.setString(2, thisUser.getId());
	                rs = ps.executeQuery();
	                byte ruleByte = HierarchyNodeAccessRuleDAO.ACCESIBILITY_DEFAULT;
	                if(rs.next()) {
	                	byte[] rule = rs.getBytes(1);
	                	if( rule.length > 1 ) {
	                		User theUser = uDAO.getByIdDecrypted(thisUser.getId(), adminGroup);
	                		rule = theUser.decrypt(rule);
	                		ruleByte = rule[0];
	                	}
	                }

	                permissions.add(
	                		new HierarchyNodeAccessRule(
	                				thisUser.getId(),
	                				thisUser.getName(),
	                				ruleByte
	        				     )
	            		);
	            } finally {
	                DatabaseConnectionUtils.close(rs);
	            }
	    	}
    	} finally {
            DatabaseConnectionUtils.close(ps);
    	}


        return permissions;
    }

    /**
     * Get all of the rules for this node.
     *
     * @param conn The connection to the database.
     * @param adminGroup The admin group to decrypt the users admin key.
     *
     * @return A Map of username to access rule.
     */

    public Set<HierarchyNodeAccessRule> getGroupAccessibilityRules( final HierarchyNode node )
    throws SQLException, GeneralSecurityException {
    	Set<HierarchyNodeAccessRule> permissions = new TreeSet<HierarchyNodeAccessRule>();

        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_GROUP_NODE_RULE_SQL);
        try {
	        ps.setString(1, node.getNodeId());

	        for(Group thisGroup : GroupDAO.getInstance().getAll()) {
	        	ps.setString(2, thisGroup.getGroupId());

		        ResultSet rs = null;
		        try {
		            rs = ps.executeQuery();
	                byte ruleByte = HierarchyNodeAccessRuleDAO.ACCESIBILITY_DEFAULT;
		            if(rs.next()) {
		            	byte[] rule = rs.getBytes(1);
		            	ruleByte = rule[0];
		            }
	            	permissions.add(
	            			new HierarchyNodeAccessRule(
	            					thisGroup.getGroupId(),
	            					thisGroup.getGroupName(),
	            					ruleByte)
            			);
		        } finally {
		            DatabaseConnectionUtils.close(rs);
		        }
	        }
        } finally {
        	DatabaseConnectionUtils.close(ps);
        }

        return permissions;
    }

    /**
     * Check if this node is usable by a specific user.
     *
     * @param conn The connection to the database.
     * @param userID The ID of the user the rule is being set for.
     *
     * @return true If the node is accessible by the user, false if not.
     */

    public void setAccessibleByUser( final HierarchyNode node,
            final User user, final byte accessibility)
        throws SQLException, GeneralSecurityException {
    	String sql;
    	if (accessibility == ACCESIBILITY_DEFAULT) {
    		sql = DELETE_USER_NODE_RULE_SQL;
    	} else {
    		if (getUserAccessibilityRule(node.getNodeId(), user) == null) {
    			sql = INSERT_USER_NODE_RULE_SQL;
    		} else {
    			sql = UPDATE_USER_NODE_RULE_SQL;
    		}
    	}

        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(sql);
        try {
            int idx = 1;
            byte[] rule = new byte[1];
            rule[0] = accessibility;
            if (sql != DELETE_USER_NODE_RULE_SQL) {
            	ps.setBytes(idx++, user.encrypt(rule));
            }
            ps.setString(idx++, node.getNodeId());
            ps.setString(idx,   user.getUserId());
            ps.executeUpdate();
        } finally {
            DatabaseConnectionUtils.close(ps);
        }
    }

    /**
     * Check if this node is usable by a specific user.
     *
     * @param conn The connection to the database.
     * @param user The user to get the rule for.
     *
     * @return true If the node is accessible by the user, false if not.
     */

    public void setAccessibleByGroup( final HierarchyNode node,
            final String groupId, final byte accessibility)
        throws SQLException, GeneralSecurityException {
    	String sql;
    	if (accessibility == ACCESIBILITY_DEFAULT) {
    		sql = DELETE_GROUP_NODE_RULE_SQL;
    	} else {
    		if (getGroupAccessibilityRule(node, groupId) == null ) {
    			sql = INSERT_GROUP_NODE_RULE_SQL;
    		} else {
    			sql = UPDATE_GROUP_NODE_RULE_SQL;
    		}
    	}

        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(sql);;
        try {
            int idx = 1;
            byte[] rule = new byte[1];
            rule[0] = accessibility;
            if (sql != DELETE_GROUP_NODE_RULE_SQL) {
            	ps.setBytes(idx++, rule);
            }
            ps.setString(idx++, node.getNodeId());
            ps.setString(idx,   groupId);
            ps.executeUpdate();
        } finally {
            DatabaseConnectionUtils.close(ps);
        }
    }

    //------------------------

    private static final class InstanceHolder {
    	static final HierarchyNodeAccessRuleDAOGroupPrecedent GROUP_PRECEDENCE_INSTANCE = new HierarchyNodeAccessRuleDAOGroupPrecedent();
    	static final HierarchyNodeAccessRuleDAOUserPrecedent  USER_PRECEDENCE_INSTANCE  = new HierarchyNodeAccessRuleDAOUserPrecedent();
    }

    public static HierarchyNodeAccessRuleDAO getInstance() {
		String precedence;
		try {
			precedence = ConfigurationDAO.getValue(ConfigurationOption.PERMISSION_PRECEDENCE);
		} catch (SQLException e) {
			precedence = "U";
		}
		if( precedence.equals("G")) {
			return InstanceHolder.GROUP_PRECEDENCE_INSTANCE;
		}

		return InstanceHolder.USER_PRECEDENCE_INSTANCE;
    }
}
