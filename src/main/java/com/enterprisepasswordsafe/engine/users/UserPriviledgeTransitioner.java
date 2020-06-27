package com.enterprisepasswordsafe.engine.users;

import com.enterprisepasswordsafe.database.*;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;

public class UserPriviledgeTransitioner {

    private UserClassifier userClassifier = new UserClassifier();

    public void makeAdmin(final User adminUser, final User theUser)
            throws SQLException, IOException, GeneralSecurityException {
        Group adminGroup = GroupDAO.getInstance().getAdminGroup(adminUser);
        makeAdmin(adminUser, adminGroup, theUser);
    }

    public void makeAdmin(final User adminUser, final Group adminGroup, final User theUser)
            throws SQLException, IOException, GeneralSecurityException {
        // Check the user is not already an admin
        if (userClassifier.isAdministrator(theUser)) {
            return;
        }

        // Decrypt the user being updateds access key using the admin groups
        // key.
        theUser.decryptAdminAccessKey(adminGroup);

        // Add the user being updated to the password admin group.
        MembershipDAO mDAO = MembershipDAO.getInstance();
        mDAO.create(theUser, adminGroup);

        // Get the password admin group and assign it the admin access key.
        Group subadminGroup = GroupDAO.getInstance().getById(Group.SUBADMIN_GROUP_ID);
        subadminGroup.setAccessKey(adminGroup.getAccessKey());

        // Add the user being updated to the password admin group.
        mDAO.create(theUser, subadminGroup);

        TamperproofEventLogDAO.getInstance().create(TamperproofEventLog.LOG_LEVEL_USER_MANIPULATION,
                adminUser, null, "{user:" + theUser.getId() + "} was given EPS administrator rights.",
                true);
    }

    public void makeSubadmin(final User adminUser, final User theUser)
            throws SQLException, IOException, GeneralSecurityException {
        Group adminGroup = GroupDAO.getInstance().getAdminGroup(adminUser);
        makeSubadmin(adminUser, adminGroup, theUser);
    }

    /**
     * Make the user a password admin.
     *
     * @param adminUser The user making the changes
     * @param theUser The user being modified
     */

    public void makeSubadmin(final User adminUser, final Group adminGroup, final User theUser)
            throws SQLException, IOException, GeneralSecurityException {
        // Check the user is not already a password admin
        if (userClassifier.isSubadministrator(theUser)) {
            return;
        }

        // Decrypt the user being updateds access key using the admin groups
        // key.
        theUser.decryptAdminAccessKey( adminGroup);

        // Get the password admin group and assign it the admin access key.
        Group subadminGroup = GroupDAO.getInstance().getById(Group.SUBADMIN_GROUP_ID);
        subadminGroup.setAccessKey(adminGroup.getAccessKey());

        // Add the user being updated to the password admin group.
        MembershipDAO mDAO = MembershipDAO.getInstance();
        mDAO.create(theUser, subadminGroup);

        // Ensure the user doesn't remain listed as an admin
        mDAO.delete(theUser, adminGroup);

        TamperproofEventLogDAO.getInstance().create(
                TamperproofEventLog.LOG_LEVEL_USER_MANIPULATION,
                adminUser,
                null,
                "{user:" + theUser.getId() +
                        "} was given password administrator rights",
                true
        );
    }

    /**
     * Change the status of the user viewing or not viewing passwords
     *
     * @param status true if the user should not be able to view passwords, false if not
     * @param theUser The user whose status should be changed.
     */

    public void setNotViewing(final User theUser, final boolean status)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {

        MembershipDAO mDAO = MembershipDAO.getInstance();
        if(status) {
            if(mDAO.getMembership(theUser, Group.NON_VIEWING_GROUP_ID) == null) {
                mDAO.create(theUser, Group.NON_VIEWING_GROUP_ID);
            }
        } else {
            if(mDAO.getMembership(theUser, Group.NON_VIEWING_GROUP_ID) != null) {
                mDAO.delete(theUser, Group.NON_VIEWING_GROUP_ID);
            }
        }
    }

    /**
     * Make the user a non-admin user.
     *
     * @param adminUser The user making the changes
     * @param theUser The user being modified
     */

    public void makeNormalUser(final User adminUser, final User theUser)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        GroupDAO gDAO = GroupDAO.getInstance();
        Group adminGroup = gDAO.getAdminGroup(adminUser);
        Group subadminGroup = gDAO.getById(Group.SUBADMIN_GROUP_ID);
        makeNormalUser( adminUser, adminGroup, subadminGroup, theUser);
    }

    /**
     * Make the user a non-admin user.
     *
     * @param adminUser The user making the changes
     * @param adminGroup The admin group.
     * @param subadminGroup The sub administrator group.
     * @param theUser The user being modified
     */

    public void makeNormalUser(final User adminUser, final Group adminGroup,
                               final Group subadminGroup, final User theUser)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        // Check the user is not already a normal user
        if (!userClassifier.isPriviledgedUser(theUser)) {
            return;
        }

        MembershipDAO mDAO = MembershipDAO.getInstance();
        mDAO.delete(theUser, adminGroup);
        mDAO.delete(theUser, subadminGroup);

        TamperproofEventLogDAO.getInstance().create( TamperproofEventLog.LOG_LEVEL_USER_MANIPULATION,
                adminUser, null, "{user:" + theUser.getId() + "} has all administration rights removed.",
                true);
    }
}
