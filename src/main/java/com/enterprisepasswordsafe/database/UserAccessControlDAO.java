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

import com.enterprisepasswordsafe.database.schema.AccessControlDAOInterface;
import com.enterprisepasswordsafe.engine.AccessControlDecryptor;
import com.enterprisepasswordsafe.engine.accesscontrol.PasswordPermission;
import com.enterprisepasswordsafe.engine.accesscontrol.UserAccessControl;
import com.enterprisepasswordsafe.engine.utils.KeyUtils;

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
		implements AccessControlDAOInterface<User, UserAccessControl> {

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

	public UserAccessControl create(final User theUser, final AccessControledObject item, PasswordPermission permission)
		throws SQLException, UnsupportedEncodingException, GeneralSecurityException {
		return create(theUser, item, permission, true);
	}

	public UserAccessControl create(final User theUser, final AccessControledObject item,
									final PasswordPermission permission, final boolean writeToDB)
		throws SQLException, GeneralSecurityException {
		if( !permission.allowsRead ) {
			UserAccessControl existingUac = get(theUser, item);
			if( existingUac != null ) {
				delete(existingUac);
			}
			return null;
		}

    	PrivateKey modifyKey = null;
    	if( permission.allowsModification ) {
    		modifyKey = item.getModifyKey();
    	}

        UserAccessControl newUac = new UserAccessControl(theUser.getId(), item.getId(), modifyKey, item.getReadKey());
        if( writeToDB ) {
        	write( newUac, theUser.getKeyEncrypter() );
        }
        return newUac;
	}

	@Override
	public void write(final User user, final UserAccessControl uac)
		throws SQLException, GeneralSecurityException
	{
		write(uac, user.getKeyEncrypter());
	}

	public void write(final UserAccessControl uac, final Encrypter encrypter )
		throws SQLException, GeneralSecurityException
	{
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(WRITE_UAC_SQL)) {
            ps.setString(1, uac.getUserId());
            ps.setString(2, uac.getItemId());
            ps.setBytes (3, KeyUtils.encryptKey(uac.getReadKey(), encrypter));
            ps.setBytes (4, KeyUtils.encryptKey(uac.getModifyKey(), encrypter));
            ps.executeUpdate();
        }
	}

	@Override
    public UserAccessControl get(final User user, final AccessControledObject item)
        throws SQLException, GeneralSecurityException {
        if (item == null) {
            return null;
        }

        return get(user, item.getId());
    }

    public UserAccessControl get(final User user, final String itemId)
        throws SQLException, GeneralSecurityException {
        if (user == null || itemId == null) {
            return null;
        }

        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_UAC_SQL)) {
            ps.setString(1, user.getId());
            ps.setString(2, itemId);
            ps.setMaxRows(1);
            try(ResultSet rs = ps.executeQuery()) {
	            return rs.next() ? buildFromResultSet(rs, user) : null;
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
        throws SQLException, GeneralSecurityException {
        if (user == null) {
            return;
        }

        List<UserAccessControl> encryptionList = new ArrayList<>();
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_ALL_UAC_FOR_USER_SQL)) {
            ps.setString(1, user.getId());
            try(ResultSet rs = ps.executeQuery()) {
	            while(rs.next()) {
	            	try {
	            		final UserAccessControl ac = buildFromResultSet(rs, user);
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
            throws SQLException {
        Set<AccessSummary> summaries = new TreeSet<>();

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
		    				canRead = (!rs.wasNull());
		    				rs.getBytes(2);	// Read the modify key
		    				canModify = (!rs.wasNull());
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
            throws SQLException, GeneralSecurityException {
    	update(uac, user.getKeyEncrypter());
    }

    public void update(final UserAccessControl uac, final Encrypter encrypter)
            throws SQLException, GeneralSecurityException {
// TODO: Look at improved update
    	delete(uac);
    	write(uac, encrypter);
    }

	static UserAccessControl buildFromResultSet(final ResultSet rs,
                                                final AccessControlDecryptor decryptor)
			throws SQLException, GeneralSecurityException {
		return UserAccessControl.builder()
				.withItemId(rs.getString(1))
				.withModifyKey(
						KeyUtils.decryptPrivateKey(rs.getBytes(1 +1), decryptor.getKeyDecrypter()))
				.withReadKey(
						KeyUtils.decryptPublicKey(rs.getBytes(1 +2), decryptor.getKeyDecrypter()))
				.withAccessorId(rs.getString(1 +3))
				.build();

	}



	//------------------------

    private static final class InstanceHolder {
    	static final UserAccessControlDAO INSTANCE = new UserAccessControlDAO();
    }

    public static UserAccessControlDAO getInstance() {
		return InstanceHolder.INSTANCE;
    }
}
