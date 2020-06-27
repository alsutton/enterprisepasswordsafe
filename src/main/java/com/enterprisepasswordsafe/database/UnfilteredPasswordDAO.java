package com.enterprisepasswordsafe.database;

import com.enterprisepasswordsafe.engine.accesscontrol.AccessControl;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;

public class UnfilteredPasswordDAO
    extends PasswordStoreManipulator {

    /**
     * The SQL statement to get a password from an ID.
     */

    private static final String GET_BY_ID =
            "SELECT " + PASSWORD_FIELDS + "  FROM passwords pass WHERE pass.password_id = ?";

    private UnfilteredPasswordDAO() {
        super(GET_BY_ID, null, null);
    }

    public Password getById(final User user, final String id)
            throws SQLException, IOException, GeneralSecurityException {
        AccessControl ac = AccessControlDAO.getInstance().getReadAccessControl(user, id);
        if( ac == null )
            return null;

        return getById(id, ac);
    }

    //------------------------

    private static final class InstanceHolder {
        static final UnfilteredPasswordDAO INSTANCE = new UnfilteredPasswordDAO();
    }

    public static UnfilteredPasswordDAO getInstance() {
        return UnfilteredPasswordDAO.InstanceHolder.INSTANCE;
    }

}
