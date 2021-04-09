package com.enterprisepasswordsafe.engine.users;

import com.enterprisepasswordsafe.database.Group;
import com.enterprisepasswordsafe.model.dao.MembershipDAO;

import java.sql.SQLException;
import java.util.Map;

/**
 * Class to identify which type of user this is. This class must be thread-safe.
 */
public class UserClassifier {
    public static final String ADMIN_USER_ID = "0";

    private final MembershipDAO membershipDAO;

    public UserClassifier() {
        this(MembershipDAO.getInstance());
    }

    UserClassifier(MembershipDAO membershipDAO) {
        this.membershipDAO = membershipDAO;
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
        return !user.getId().equals(ADMIN_USER_ID)
                && membershipDAO.isMemberOf(user.getId(), Group.NON_VIEWING_GROUP_ID);
    }

    public UserLevel getUserLevelFor(User user) throws SQLException {
        if(isAdministrator(user)) {
            return UserLevel.ADMINISTRATOR;
        }
        if(isSubadministrator(user)) {
            return UserLevel.PRIVILEGED;
        }
        return UserLevel.REGULAR;
    }

    public UserLevel getUserLevelFrom(Map<String, Object> userMemberships) {
        if(userMemberships.containsKey(Group.ADMIN_GROUP_ID)) {
            return UserLevel.ADMINISTRATOR;
        }
        if(userMemberships.containsKey(Group.SUBADMIN_GROUP_ID)) {
            return UserLevel.PRIVILEGED;
        }
        return UserLevel.REGULAR;
    }
}
