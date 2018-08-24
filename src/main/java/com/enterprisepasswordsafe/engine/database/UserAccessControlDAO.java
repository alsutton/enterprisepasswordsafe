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
import java.security.PrivateKey;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;

import com.enterprisepasswordsafe.engine.database.schema.AccessControlDAOInterface;
import com.enterprisepasswordsafe.engine.utils.DatabaseConnectionUtils;
import com.enterprisepasswordsafe.engine.utils.InvalidLicenceException;
import com.enterprisepasswordsafe.engine.utils.KeyUtils;
import com.enterprisepasswordsafe.proguard.ExternalInterface;

/**
 * Data access object for the user access control.
 */

public final class UserAccessControlDAO
		implements ExternalInterface, AccessControlDAOInterface<User, UserAccessControl> {

    /**
     * The fields needed in a ResultSet to construct a user access control.
     */

    public static final String UAC_FIELDS = " uac.item_id, uac.mkey, uac.rkey, uac.user_id ";

    public static final int UAC_FIELD_COUNT = 1 + AccessControl.ACCESS_CONTROL_FIELD_COUNT;

    /**
     * The SQL statement to get a category.
     */

    private static final String WRITE_UAC_SQL =
              "INSERT INTO user_access_control(user_id, item_id, rkey, mkey)"
            + "                         VALUES(      ?,       ?,        ?,          ?)";

    /**
     * The SQL statement to get the uac for a given username/item
     * combination.
     */

    private static final String GET_UAC_SQL =
            "SELECT " + UAC_FIELDS
            + "  FROM user_access_control uac "
            + " WHERE uac.user_id = ? "
            + "   AND uac.item_id = ? "
            + "   AND uac.rkey is not null";


    /**
     * The SQL statement to get the uac for a given username/item
     * combination.
     */

    private static final String GET_ALL_UAC_FOR_USER_SQL =
            "SELECT " + UAC_FIELDS
            + "  FROM user_access_control uac "
            + " WHERE uac.user_id = ? ";

    /**
     * The SQL to delete a UAC.
     */

    private static final String DELETE_SQL =
            "DELETE FROM user_access_control "
            + " WHERE user_id = ? "
            + "   AND item_id = ?";

    /**
     * The SQL to delete all UACs for an item.
     */

    private static final String DELETE_ALL_FOR_ITEM_SQL =
            "DELETE FROM user_access_control "
            + " WHERE item_id = ?";

    /**
     * The SQL to get all group access controls for all groups with access to
     * this password.
     */

    private static final String GET_UAC_SUMMARIES_UAC_SQL =
              "SELECT uac.rkey, uac.mkey"
            + "  FROM user_access_control uac "
            + " WHERE uac.item_id = ? "
            + "   AND uac.user_id = ?"
            + "	  AND uac.rkey is not null ";

    /**
     * The SQL to get all group access controls for all groups with access to
     * this password.
     */

    private static final String GET_UAC_SUMMARIES_UAR_SQL =
              "SELECT uar.role"
            + "  FROM user_access_roles uar "
            + " WHERE uar.item_id = ? "
    		+ "   AND uar.actor_id = ?";

	/**
	 * Private constructor to prevent instantiation
	 */

	private UserAccessControlDAO( ) {
		super();
	}

	/**
	 * Create a UAC for a user and password.
	 *
	 * @param theUser The user we are creating the UAC for
	 * @param theObject The object to create the UAC for.
	 * @throws GeneralSecurityException
	 * @throws UnsupportedEncodingException
	 */

	public UserAccessControl create(final User theUser, final AccessControledObject item,
			boolean allowRead, boolean allowModify)
		throws SQLException, UnsupportedEncodingException, GeneralSecurityException {
		return create(theUser, item, allowRead, allowModify, true);
	}
	/**
	 * Create a UAC for a user and password.
	 *
	 * @param theUser The user we are creating the UAC for
	 * @param theObject The object to create the UAC for.
	 * @throws GeneralSecurityException
	 * @throws UnsupportedEncodingException
	 */

	public UserAccessControl create(final User theUser, final AccessControledObject item,
			final boolean allowRead, final boolean allowModify, final boolean writeToDB)
		throws SQLException, UnsupportedEncodingException, GeneralSecurityException {
		if( !allowRead ) {
			UserAccessControl existingUac = getUac(theUser, item);
			if( existingUac != null ) {
				delete(existingUac);
			}
			return null;
		}

    	PrivateKey modifyKey = null;
    	if( allowModify ) {
    		modifyKey = item.getModifyKey();
    	}

        UserAccessControl newUac =
        	new UserAccessControl(theUser.getUserId(), item.getId(), modifyKey, item.getReadKey());
        if( writeToDB ) {
        	write( newUac, theUser.getKeyEncrypter() );
        }
        return newUac;
	}

	/**
	 * Write a UAC for a user.
	 *
	 * @param uac The UAC to write
	 * @param user The user to write the UAC for
	 *
	 * @throws SQLException
	 * @throws GeneralSecurityException
	 * @throws UnsupportedEncodingException
	 */

	public void write(final UserAccessControl uac, final User user )
		throws SQLException, UnsupportedEncodingException, GeneralSecurityException
	{
		write(uac, user.getKeyEncrypter());
	}

	/**
	 * Write a UAC for a user.
	 *
	 * @param uac The UAC to write
	 * @param encrypter The encrypter to use to write the entry
	 *
	 * @throws SQLException
	 * @throws GeneralSecurityException
	 * @throws UnsupportedEncodingException
	 */

	public void write(final UserAccessControl uac, final Encrypter encrypter )
		throws SQLException, UnsupportedEncodingException, GeneralSecurityException
	{
        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(WRITE_UAC_SQL);
        try {
            ps.setString(1, uac.getUserId());
            ps.setString(2, uac.getItemId());
            ps.setBytes (3, KeyUtils.encryptKey(uac.getReadKey(), encrypter));
            ps.setBytes (4, KeyUtils.encryptKey(uac.getModifyKey(), encrypter));
            ps.executeUpdate();
        } finally {
        	ps.close();
        }
	}

    /**
     * Gets the data about an individual user access control.
     *
     * @param conn
     *            The connection to the database.
     * @param user
     *            The user for whom the UAC is active
     * @param itemId
     *            The ID of the item to get the UAC for.
     *
     * @return The user access control.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem decrypting the data.
     * @throws UnsupportedEncodingException
     */

    public UserAccessControl getUac(final User user, final AccessControledObject item)
        throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        if (item == null) {
            return null;
        }

        return getUac(user, item.getId());
    }

    /**
     * Gets the data about an individual user access control.
     *
     * @param conn
     *            The connection to the database.
     * @param user
     *            The user for whom the UAC is active
     * @param itemId
     *            The ID of the item to get the UAC for.
     *
     * @return The user access control.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem decrypting the data.
     * @throws UnsupportedEncodingException
     */

    public UserAccessControl getUac(final User user, final String itemId)
        throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        if (user == null || itemId == null) {
            return null;
        }

        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_UAC_SQL);
        try {
            ps.setString(1, user.getUserId());
            ps.setString(2, itemId);
            ps.setMaxRows(1);
            ResultSet rs = ps.executeQuery();
            try {
	            if (rs.next()) {
	                return new UserAccessControl(rs, 1, user);
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
     * Delete this access control.
     *
     * @param conn The connection to the database.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     */

    public void delete(UserAccessControl uac)
        throws SQLException {
    	PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(DELETE_SQL);
        try {
            ps.setString(1, uac.getUserId());
            ps.setString(2, uac.getItemId());
            ps.executeUpdate();
        } finally {
        	DatabaseConnectionUtils.close(ps);
        }
    }

    /**
     * Delete this access control.
     *
     * @param conn The connection to the database.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     */

    public void deleteAllForItem(AccessControledObject aco)
        throws SQLException {
    	PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(DELETE_ALL_FOR_ITEM_SQL);
        try {
            ps.setString(1, aco.getId());
            ps.executeUpdate();
        } finally {
        	DatabaseConnectionUtils.close(ps);
        }
    }

    /**
     * Delete this access control.
     *
     * @param conn The connection to the database.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     *
     * @throws GeneralSecurityException
     * @throws UnsupportedEncodingException
     */

    public void updateEncryptionOnKeys(final User user,  final Encrypter encrypter)
        throws SQLException, UnsupportedEncodingException, GeneralSecurityException {
        if (user == null) {
            return;
        }

        List<UserAccessControl> encryptionList = new ArrayList<UserAccessControl>();
        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_ALL_UAC_FOR_USER_SQL);
        try {
            ps.setString(1, user.getUserId());
            ResultSet rs = ps.executeQuery();
            try {
	            while(rs.next()) {
	            	try {
	            		final UserAccessControl ac = new UserAccessControl(rs, 1, user);
	            		if(ac.getReadKey() != null || ac.getModifyKey() != null) {
	            			encryptionList.add(ac);
	            		}
	            	} catch(BadPaddingException e) {
	            		Logger.getAnonymousLogger().log(Level.SEVERE, "User "+user.getUserName()+" encountered a problem on key update.", e);
	            	}
	            }
            } finally {
                DatabaseConnectionUtils.close(rs);
            }
        } finally {
        	DatabaseConnectionUtils.close(ps);
        }

        for(UserAccessControl ac : encryptionList ) {
        	update(ac, encrypter);
        }
    }

    /**
     * Get a sorted user set of access summaries for this password.
     *
     * @param conn
     *            The connection to the database.
     *
     * @return The Set of access summaries.
     *
     * @throws SQLException
     *             Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException
     *             Thrown if there is a problem with the access credentials.
     * @throws UnsupportedEncodingException
     */

    public Set<AccessSummary> getSummaries(final AccessControledObject item)
            throws GeneralSecurityException, SQLException, UnsupportedEncodingException {
        Set<AccessSummary> summaries = new TreeSet<AccessSummary>();

    	PreparedStatement uacPS = BOMFactory.getCurrentConntection().prepareStatement(GET_UAC_SUMMARIES_UAC_SQL);
    	try {
        	PreparedStatement uarPS = BOMFactory.getCurrentConntection().prepareStatement(GET_UAC_SUMMARIES_UAR_SQL);
        	try {
	    		uacPS.setString(1, item.getId());
	    		uarPS.setString(1, item.getId());

	    		for(User thisUser : UserDAO.getInstance().getAll()) {
		    		boolean canRead = false;
		    		boolean canModify = false;
		    		uacPS.setString(2, thisUser.getUserId());
		    		uacPS.setMaxRows(1);
		    		ResultSet rs = uacPS.executeQuery();
		    		try {
		    			if( rs.next() ) {
		    				rs.getBytes(1);	// Read the read key
		    				canRead = (rs.wasNull() == false);
		    				rs.getBytes(2);	// Read the modify key
		    				canModify = (rs.wasNull() == false);
		    			}
		    		} finally {
		    			DatabaseConnectionUtils.close(rs);
		    		}

		    		boolean canApproveRARequest = false;
		    		boolean canViewHistory = false;
		    		uarPS.setString(2, thisUser.getUserId());
		    		rs = uarPS.executeQuery();
		    		try {
		    			while( rs.next() ) {
		    				String role = rs.getString(1);
		    				if( rs.wasNull() ) {
		    					continue;
		    				}

		    				if( role.equals(AccessRole.APPROVER_ROLE) ) {
		    					canApproveRARequest = true;
		    				} else if (role.equals(AccessRole.HISTORYVIEWER_ROLE)) {
		    					canViewHistory = true;
		    				}
		    			}
		    		} finally {
		    			DatabaseConnectionUtils.close(rs);
		    		}

	            	AccessSummary gas =
	            		new AccessSummary(
	            				thisUser.getUserId(),
	            				thisUser.getUserName(),
	            				canRead,
	            				canModify,
	            				canApproveRARequest,
	            				canViewHistory
	        				);
	            	summaries.add(gas);
		    	}

	    		return summaries;
        	} finally {
        		DatabaseConnectionUtils.close(uarPS);
        	}
    	} finally {
    		DatabaseConnectionUtils.close(uacPS);
    	}
    }

    /**
     * Writes a UAC entry to the database.
     *
     * @param uac The UAC to write.
     * @param user The user to encrypt it for.
     *
     * @throws SQLException Thrown if there is a problem accessing thda database.
     * @throws GeneralSecurityException Thrown if there is a problem encrypting the user data.
     * @throws UnsupportedEncodingException
     * @throws InvalidLicenceException Thrown if the licence is not valid.
     * @throws IOException Thrown if there is an IO problem.
     */

    public void update(final User user, final UserAccessControl uac)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
    	update(uac, user.getKeyEncrypter());
    }

    /**
     * Writes a UAC entry to the database.
     *
     * @param conn The connection to the database.
     * @param uac The UAC to write.
     *
     * @throws SQLException Thrown if there is a problem accessing thda database.
     * @throws GeneralSecurityException Thrown if there is a problem encrypting the user data.
     * @throws UnsupportedEncodingException
     * @throws InvalidLicenceException Thrown if the licence is not valid.
     * @throws IOException Thrown if there is an IO problem.
     */

    public void update(final UserAccessControl uac, final Encrypter encrypter)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
// TODO: Look at improved update
    	delete(uac);
    	write(uac, encrypter);
    }

    //------------------------

    private static final class InstanceHolder {
    	static final UserAccessControlDAO INSTANCE = new UserAccessControlDAO();
    }

    public static UserAccessControlDAO getInstance() {
		return InstanceHolder.INSTANCE;
    }
}
