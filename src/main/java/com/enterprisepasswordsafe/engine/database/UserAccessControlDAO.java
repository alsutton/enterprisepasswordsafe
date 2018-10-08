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

import com.enterprisepasswordsafe.engine.database.schema.AccessControlDAOInterface;
import com.enterprisepasswordsafe.engine.utils.KeyUtils;
import com.enterprisepasswordsafe.proguard.ExternalInterface;

import javax.crypto.BadPaddingException;
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

public final class UserAccessControlDAO
		extends AbstractAccessControlDAO
		implements ExternalInterface, AccessControlDAOInterface<User, UserAccessControl> {

    public static final String UAC_FIELDS = " uac.item_id, uac.mkey, uac.rkey, uac.user_id ";

    private static final String WRITE_UAC_SQL =
              "INSERT INTO user_access_control(user_id, item_id, rkey, mkey) VALUES( ?, ?, ?, ?)";

    private static final String GET_UAC_SQL =
            "SELECT " + UAC_FIELDS + "  FROM user_access_control uac WHERE uac.user_id = ? AND uac.item_id = ? "
            + "   AND uac.rkey is not null";

    private static final String GET_ALL_UAC_FOR_USER_SQL =
            "SELECT " + UAC_FIELDS + "  FROM user_access_control uac WHERE uac.user_id = ? ";

    private static final String DELETE_SQL =
            "DELETE FROM user_access_control WHERE user_id = ? AND item_id = ?";

    private static final String DELETE_ALL_FOR_ITEM_SQL =
            "DELETE FROM user_access_control WHERE item_id = ?";

    private static final String GET_UAC_SUMMARIES_UAC_SQL =
              "SELECT uac.rkey, uac.mkey FROM user_access_control uac "
            + " WHERE uac.item_id = ? AND uac.user_id = ? AND uac.rkey is not null ";

    private static final String GET_UAC_SUMMARIES_UAR_SQL =
              "SELECT uar.role  FROM user_access_roles uar WHERE uar.item_id = ? AND uar.actor_id = ?";

	private UserAccessControlDAO( ) {
		super();
	}

	public UserAccessControl create(final User theUser, final AccessControledObject item,
			boolean allowRead, boolean allowModify)
		throws SQLException, UnsupportedEncodingException, GeneralSecurityException {
		return create(theUser, item, allowRead, allowModify, true);
	}

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

        UserAccessControl newUac = new UserAccessControl(theUser.getId(), item.getId(), modifyKey, item.getReadKey());
        if( writeToDB ) {
        	write( newUac, theUser.getKeyEncrypter() );
        }
        return newUac;
	}

	public void write(final UserAccessControl uac, final User user )
		throws SQLException, UnsupportedEncodingException, GeneralSecurityException
	{
		write(uac, user.getKeyEncrypter());
	}

	public void write(final UserAccessControl uac, final Encrypter encrypter )
		throws SQLException, UnsupportedEncodingException, GeneralSecurityException
	{
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(WRITE_UAC_SQL)) {
            ps.setString(1, uac.getUserId());
            ps.setString(2, uac.getItemId());
            ps.setBytes (3, KeyUtils.encryptKey(uac.getReadKey(), encrypter));
            ps.setBytes (4, KeyUtils.encryptKey(uac.getModifyKey(), encrypter));
            ps.executeUpdate();
        }
	}

    public UserAccessControl getUac(final User user, final AccessControledObject item)
        throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        if (item == null) {
            return null;
        }

        return getUac(user, item.getId());
    }

    public UserAccessControl getUac(final User user, final String itemId)
        throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        if (user == null || itemId == null) {
            return null;
        }

        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_UAC_SQL)) {
            ps.setString(1, user.getId());
            ps.setString(2, itemId);
            ps.setMaxRows(1);
            try(ResultSet rs = ps.executeQuery()) {
	            return rs.next() ? new UserAccessControl(rs, 1, user) : null;
            }
        }
    }

    public void delete(UserAccessControl uac)
        throws SQLException {
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(DELETE_SQL)) {
            ps.setString(1, uac.getUserId());
            ps.setString(2, uac.getItemId());
            ps.executeUpdate();
        }
    }

    public void deleteAllForItem(AccessControledObject aco)
        throws SQLException {
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(DELETE_ALL_FOR_ITEM_SQL)) {
            ps.setString(1, aco.getId());
            ps.executeUpdate();
        }
    }

    public void updateEncryptionOnKeys(final User user,  final Encrypter encrypter)
        throws SQLException, UnsupportedEncodingException, GeneralSecurityException {
        if (user == null) {
            return;
        }

        List<UserAccessControl> encryptionList = new ArrayList<UserAccessControl>();
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_ALL_UAC_FOR_USER_SQL)) {
            ps.setString(1, user.getId());
            try(ResultSet rs = ps.executeQuery()) {
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
            }
        }

        for(UserAccessControl ac : encryptionList ) {
        	update(ac, encrypter);
        }
    }

    public Set<AccessSummary> getSummaries(final AccessControledObject item)
            throws GeneralSecurityException, SQLException, UnsupportedEncodingException {
        Set<AccessSummary> summaries = new TreeSet<AccessSummary>();

    	try(PreparedStatement uacPS = BOMFactory.getCurrentConntection().prepareStatement(GET_UAC_SUMMARIES_UAC_SQL)) {
        	try(PreparedStatement uarPS = BOMFactory.getCurrentConntection().prepareStatement(GET_UAC_SUMMARIES_UAR_SQL)) {
	    		uacPS.setString(1, item.getId());
	    		uarPS.setString(1, item.getId());

	    		for(User thisUser : UserDAO.getInstance().getAll()) {
		    		boolean canRead = false;
		    		boolean canModify = false;
		    		uacPS.setString(2, thisUser.getId());
		    		uacPS.setMaxRows(1);
		    		try(ResultSet rs = uacPS.executeQuery()) {
		    			if( rs.next() ) {
		    				rs.getBytes(1);	// Read the read key
		    				canRead = (rs.wasNull() == false);
		    				rs.getBytes(2);	// Read the modify key
		    				canModify = (rs.wasNull() == false);
		    			}
		    		}

		    		uarPS.setString(2, thisUser.getId());
					AbstractAccessControlDAO.Permissions permissions = getPermissions(uarPS);
	            	AccessSummary gas = new AccessSummary(thisUser.getId(), thisUser.getUserName(),
	            				canRead, canModify, permissions.canApproveRARequest, permissions.canViewHistory);
	            	summaries.add(gas);
		    	}

	    		return summaries;
        	}
    	}
    }

    public void update(final User user, final UserAccessControl uac)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
    	update(uac, user.getKeyEncrypter());
    }

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
