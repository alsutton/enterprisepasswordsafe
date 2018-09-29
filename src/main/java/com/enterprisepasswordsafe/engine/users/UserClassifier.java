package com.enterprisepasswordsafe.engine.users;

import com.enterprisepasswordsafe.engine.database.Group;
import com.enterprisepasswordsafe.engine.database.MembershipDAO;
import com.enterprisepasswordsafe.engine.database.User;

import java.sql.SQLException;

/**
 * Class to identify which type of user this is. This class must be thread-safe.
 */
public class UserClassifier {
    public static final String ADMIN_USER_ID = "0";

    private MembershipDAO membershipDAO;

    public UserClassifier() {
        membershipDAO = MembershipDAO.getInstance();
    }

    public boolean isMasterAdmin(User user) {
        return ADMIN_USER_ID.equals(user.getId());
    }

    public boolean isPriviledgedUser(User user)
            throws SQLException {
        return isAdministrator(user) || isSubadministrator(user);
    }

    public boolean isAdministrator(User user)
            throws SQLException {
        return membershipDAO.isMemberOf(user.getId(), Group.ADMIN_GROUP_ID);
    }

    public boolean isSubadministrator(User user)
            throws SQLException {
        return membershipDAO.isMemberOf(user.getId(), Group.SUBADMIN_GROUP_ID);
    }

    public boolean isNonViewingUser(User user)
            throws SQLException {
        return (!user.getId().equals(ADMIN_USER_ID))
                && membershipDAO.isMemberOf(user.getId(), Group.NON_VIEWING_GROUP_ID);
    }
}
