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
            "SELECT setting FROM hierarchy_access_control WHERE node_id = ? AND user_id = ?";

    /**
     * SQL to get the access rule for a node and user.
     */

    private static final String GET_NODE_RULES_SQL =
            "SELECT hac.setting FROM hierarchy_access_control hac WHERE node_id = ? AND user_id = ? ";

    /**
     * SQL to insert an access rule for a node and user.
     */

    private static final String INSERT_USER_NODE_RULE_SQL =
           "INSERT INTO hierarchy_access_control(setting, node_id, user_id) VALUES(?, ?, ?) ";

    /**
     * SQL to update an access rule for a node and user.
     */

    private static final String UPDATE_USER_NODE_RULE_SQL =
           "UPDATE hierarchy_access_control SET setting = ? WHERE node_id = ? AND user_id = ? ";

    /**
     * SQL to insert an access rule for a node and user.
     */

    private static final String DELETE_USER_NODE_RULE_SQL =
           "DELETE FROM hierarchy_access_control WHERE node_id = ? AND user_id = ? ";

    /**
     * SQL to get the access rule for a node and user via the groups
     * the user is a member of.
     */

    private static final String GET_USERS_GROUP_NODE_RULES_SQL =
            "SELECT hgac.setting FROM hierarchy_group_access_control hgac, membership mem "
        +   " WHERE hgac.node_id = ? AND hgac.group_id = mem.group_id AND mem.user_id = ?";

    /**
     * SQL to get the access rule for a node and group.
     */

    private static final String GET_GROUP_NODE_RULE_SQL =
            "SELECT setting FROM hierarchy_group_access_control WHERE node_id = ? AND group_id = ? ";

    /**
     * SQL to insert an access rule for a node and user.
     */

    private static final String INSERT_GROUP_NODE_RULE_SQL =
           "INSERT INTO hierarchy_group_access_control(setting, node_id, group_id) VALUES(?, ?, ?) ";

    /**
     * SQL to update an access rule for a node and user.
     */

    private static final String UPDATE_GROUP_NODE_RULE_SQL =
           "UPDATE hierarchy_group_access_control SET setting = ? WHERE node_id = ? AND group_id = ? ";

    /**
     * SQL to insert an access rule for a node and user.
     */

    private static final String DELETE_GROUP_NODE_RULE_SQL =
           "DELETE FROM hierarchy_group_access_control WHERE node_id = ? AND group_id = ? ";

    public byte getAccessibilityForUser( final HierarchyNode node, final User user)
        throws SQLException, GeneralSecurityException {
    	return getAccessibilityForUser( node.getNodeId(), user, true);
    }

    public byte getAccessibilityForUser( final String nodeId, final User user)
        throws SQLException, GeneralSecurityException {
        	return getAccessibilityForUser( nodeId, user, true);
	}

    public abstract byte getAccessibilityForUser( final String nodeId, final User user, boolean recurse)
        throws SQLException, GeneralSecurityException;

    protected byte[] getUserAccessibilityRule( final String nodeId, final User user)
        throws SQLException {
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_USER_NODE_RULE_SQL)) {
            ps.setString(1, nodeId);
            ps.setString(2, user.getId());

	        try(ResultSet rs = ps.executeQuery()) {
	            return rs.next() ? rs.getBytes(1) : null;
	        }
        }
    }

    protected List<byte[]> getUsersGroupAccessibilityRules( final String nodeId, final User user)
        throws SQLException {
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_USERS_GROUP_NODE_RULES_SQL)) {
            ps.setString(1, nodeId);
            ps.setString(2, user.getId());
            try(ResultSet rs = ps.executeQuery()) {
	        	List<byte[]> ruleList = new ArrayList<>();
	            while(rs.next()) {
	                ruleList.add( rs.getBytes(1) );
	            }
	            return ruleList;
        	}
        }
    }

    protected byte[] getGroupAccessibilityRule( final HierarchyNode node, final String groupId)
        throws SQLException {
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_GROUP_NODE_RULE_SQL)) {
            ps.setString(1, node.getNodeId());
            ps.setString(2,   groupId);
			ps.setMaxRows(1);
            try(ResultSet rs = ps.executeQuery()) {
            	return rs.next() ? rs.getBytes(1) : null;
            }
        }
    }

    public Set<HierarchyNodeAccessRule> getAccessibilityRules( final HierarchyNode node, final Group adminGroup)
    	throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
    	Set<HierarchyNodeAccessRule> permissions = new TreeSet<>();

    	try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_NODE_RULES_SQL)) {
	        ps.setString(1, node.getNodeId());

			UserDAO uDAO = UserDAO.getInstance();
	        UserSummaryDAO usDAO = UserSummaryDAO.getInstance();
	    	for(UserSummary thisUser : usDAO.getSummaryListExcludingAdmin()) {
				ps.setString(2, thisUser.getId());
	            try(ResultSet rs = ps.executeQuery()) {
	                byte ruleByte = HierarchyNodeAccessRuleDAO.ACCESIBILITY_DEFAULT;
	                if(rs.next()) {
	                	byte[] rule = rs.getBytes(1);
	                	if( rule.length > 1 ) {
	                		User theUser = uDAO.getByIdDecrypted(thisUser.getId(), adminGroup);
	                		rule = theUser.getKeyDecrypter().decrypt(rule);
	                		ruleByte = rule[0];
	                	}
	                }

	                permissions.add(new HierarchyNodeAccessRule(thisUser.getId(), thisUser.getName(), ruleByte));
	            }
	    	}
    	}

        return permissions;
    }

    public Set<HierarchyNodeAccessRule> getGroupAccessibilityRules( final HierarchyNode node )
	    throws SQLException {
    	Set<HierarchyNodeAccessRule> permissions = new TreeSet<>();
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_GROUP_NODE_RULE_SQL)) {
	        ps.setString(1, node.getNodeId());

	        for(Group thisGroup : GroupDAO.getInstance().getAll()) {
	        	ps.setString(2, thisGroup.getGroupId());
		        try(ResultSet rs = ps.executeQuery()) {
	                byte ruleByte = HierarchyNodeAccessRuleDAO.ACCESIBILITY_DEFAULT;
		            if(rs.next()) {
		            	byte[] rule = rs.getBytes(1);
		            	ruleByte = rule[0];
		            }
	            	permissions.add(new HierarchyNodeAccessRule(thisGroup.getGroupId(),thisGroup.getGroupName(),ruleByte));
		        }
	        }
        }

        return permissions;
    }

    public void setAccessibleByUser( final HierarchyNode node, final User user, final byte accessibility)
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

        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(sql)) {
            int idx = 1;
            byte[] rule = new byte[1];
            rule[0] = accessibility;
            if (!DELETE_USER_NODE_RULE_SQL.equals(sql)) {
            	ps.setBytes(idx++, user.getKeyEncrypter().encrypt(rule));
            }
            ps.setString(idx++, node.getNodeId());
            ps.setString(idx,   user.getId());
            ps.executeUpdate();
        }
    }

    public void setAccessibleByGroup( final HierarchyNode node, final String groupId, final byte accessibility)
        throws SQLException {
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

        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(sql)) {
            int idx = 1;
            byte[] rule = new byte[1];
            rule[0] = accessibility;
            if (!DELETE_GROUP_NODE_RULE_SQL.equals(sql)) {
            	ps.setBytes(idx++, rule);
            }
            ps.setString(idx++, node.getNodeId());
            ps.setString(idx,   groupId);
            ps.executeUpdate();
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
