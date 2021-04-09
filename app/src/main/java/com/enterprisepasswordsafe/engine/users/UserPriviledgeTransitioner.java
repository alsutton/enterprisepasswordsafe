package com.enterprisepasswordsafe.engine.users;

import com.enterprisepasswordsafe.logging.LogStore;
import com.enterprisepasswordsafe.model.DAORepository;
import com.enterprisepasswordsafe.model.LogEventClass;
import com.enterprisepasswordsafe.model.ReservedGroups;
import com.enterprisepasswordsafe.model.dao.GroupDAO;
import com.enterprisepasswordsafe.model.dao.MembershipDAO;
import com.enterprisepasswordsafe.model.persisted.Group;
import com.enterprisepasswordsafe.model.persisted.User;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;

public class UserPriviledgeTransitioner {

    private final DAORepository daoRepository;
    private final LogStore logStore;

    public UserPriviledgeTransitioner(DAORepository daoRepository, LogStore logStore) {
        this.daoRepository = daoRepository;
        this.logStore = logStore;
    }

    public void makeAdmin(final User adminUser, final User theUser)
            throws GeneralSecurityException {
        Group adminGroup = daoRepository.getGroupDAO().getAdminGroup(adminUser);
        makeAdmin(adminUser, adminGroup, theUser);
    }

    public void makeAdmin(final User adminUser, final Group adminGroup, final User user)
            throws GeneralSecurityException {
        MembershipDAO membershipDAO = daoRepository.getMembershipDAO();
        // Check the user is not already an admin
        if (membershipDAO.isAdminUser(user)) {
            return;
        }

        membershipDAO.create(user, adminGroup);

        Group subadminGroup =
                daoRepository
                        .getGroupDAO()
                        .getByIdWithKeyAvailable(ReservedGroups.SUBADMIN, adminUser);
        membershipDAO.create(user, subadminGroup);

        logStore.log(LogEventClass.USER_MANIPULATION, adminUser, null,
                "{user:" + user.getId() + "} was given EPS administrator rights.",
                true);
    }

    public void makeSubadmin(final User adminUser, final User theUser)
            throws GeneralSecurityException {
        Group adminGroup = daoRepository.getGroupDAO().getAdminGroup(adminUser);
        makeSubadmin(adminUser, adminGroup, theUser);
    }

    /**
     * Make the user a password admin.
     *
     * @param adminUser The user making the changes
     * @param theUser The user being modified
     */

    public void makeSubadmin(final User adminUser, final Group adminGroup, final User theUser)
            throws GeneralSecurityException {
        MembershipDAO membershipDAO = daoRepository.getMembershipDAO();
        if (membershipDAO.isSubadminUser(theUser) && !membershipDAO.isAdminUser(theUser)) {
            return;
        }

        Group subadminGroup =
                daoRepository
                        .getGroupDAO()
                        .getByIdWithKeyAvailable(ReservedGroups.SUBADMIN, adminUser);
        membershipDAO.create(theUser, subadminGroup);
        membershipDAO.delete(theUser, adminGroup);

        logStore.log(LogEventClass.USER_MANIPULATION, adminUser, null,
                "{user:" + theUser.getId() + "} was given password administrator rights",
                true);
    }

    /**
     * Change the status of the user viewing or not viewing passwords.
     *
     * @param adminUser the administrator performing the change.
     * @param user The user whose status should be changed.
     * @param canView true if the user should be able to view passwords, false if not
     */

    public void setViewingAbility(final User adminUser, final User user, final boolean canView)
            throws GeneralSecurityException {
        if(canView == user.getCanViewPasswords()) {
            // No change so no transition needed.
            return;
        }

        if(canView) {
            logStore.log(LogEventClass.USER_MANIPULATION, adminUser, null,
                    "{user:" + user.getId() +
                            "} had the ability to view passwords added by {user:" +
                            adminUser.getId() + "}.",
                    true);
        } else if (user.getCanViewPasswords()) {
            logStore.log(LogEventClass.USER_MANIPULATION, adminUser, null,
                    "{user:" + user.getId() +
                            "} had their ability to view passwords removed by {user:" +
                            adminUser.getId() + "}.",
                    true);
        }

        user.setCanViewPasswords(canView);
        daoRepository.getUserDAO().store(user);
    }

    /**
     * Make the user a non-admin user.
     *
     * @param adminUser The user making the changes
     * @param theUser The user being modified
     */

    public void makeNormalUser(final User adminUser, final User theUser)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        GroupDAO gDAO = daoRepository.getGroupDAO();
        Group adminGroup = gDAO.getAdminGroup(adminUser);
        Group subadminGroup = gDAO.getById(ReservedGroups.SUBADMIN.getId());
        makeNormalUser( adminUser, adminGroup, subadminGroup, theUser);
    }

    /**
     * Make the user a non-admin user.
     *
     * @param adminUser The user making the changes
     * @param adminGroup The admin group.
     * @param subadminGroup The sub administrator group.
     * @param user The user being modified
     */

    public void makeNormalUser(final User adminUser, final Group adminGroup,
                               final Group subadminGroup, final User user)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        // Check the user is not already a normal user
        MembershipDAO membershipDAO = daoRepository.getMembershipDAO();
        if (!membershipDAO.isPriviledgedUser(user)) {
            return;
        }

        membershipDAO.delete(user, adminGroup);
        membershipDAO.delete(user, subadminGroup);

        logStore.log( LogEventClass.USER_MANIPULATION, adminUser, null,
                "{user:" + user.getId() + "} has all administration rights removed.",
                true);
    }
}
