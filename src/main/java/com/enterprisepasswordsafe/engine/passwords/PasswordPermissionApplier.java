package com.enterprisepasswordsafe.engine.passwords;

import com.enterprisepasswordsafe.engine.database.*;
import com.enterprisepasswordsafe.engine.database.schema.AccessControlDAOInterface;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

public class PasswordPermissionApplier {

    private final GroupAccessControlDAO groupAccessControlDAO;
    private final GroupDAO groupDAO;
    private final HierarchyNodePermissionDAO hierarchyNodePermissionDAO;
    private final UserAccessControlDAO userAccessControlDAO;
    private final UserDAO userDAO;

    public PasswordPermissionApplier() {
        groupAccessControlDAO = GroupAccessControlDAO.getInstance();
        groupDAO = GroupDAO.getInstance();
        hierarchyNodePermissionDAO = new HierarchyNodePermissionDAO();
        userAccessControlDAO = UserAccessControlDAO.getInstance();
        userDAO = UserDAO.getInstance();
    }

    public void setDefaultPermissions(final Password newPassword, final String parentNodeId, final Group adminGroup)
            throws UnsupportedEncodingException, SQLException, GeneralSecurityException {
        Map<String,String> uPerms = new HashMap<>();
        Map<String,String> gPerms = new HashMap<>();
        hierarchyNodePermissionDAO.getCombinedDefaultPermissionsForNode(parentNodeId, uPerms, gPerms);

        setUserDefaults(uPerms, adminGroup, newPassword);
        setGroupDefaults(gPerms, adminGroup, newPassword);

    }

    private void setUserDefaults(Map<String,String> uPerms, Group adminGroup, Password newPassword)
            throws GeneralSecurityException, UnsupportedEncodingException, SQLException {

        for(Map.Entry<String, String> thisEntry : uPerms.entrySet()) {
            String userId = thisEntry.getKey();
            User theUser = userDAO.getByIdDecrypted(userId, adminGroup);
            if( theUser != null ) {
                addPermission(theUser, newPassword, userAccessControlDAO, thisEntry.getValue());
            }
        }
    }

    private void setGroupDefaults(Map<String,String> gPerms, Group adminGroup, Password newPassword)
            throws GeneralSecurityException, UnsupportedEncodingException, SQLException {
        final User adminUser = userDAO.getAdminUser(adminGroup);
        for(Map.Entry<String,String> thisEntry : gPerms.entrySet()) {
            final String groupId = thisEntry.getKey();
            Group theGroup = groupDAO.getByIdDecrypted(groupId, adminUser);
            if( theGroup != null ) {
                addPermission(theGroup, newPassword, groupAccessControlDAO, thisEntry.getValue());
            }
        }
    }

    private void addPermission(EntityWithAccessRights entity, Password newPassword,
                               AccessControlDAOInterface acDAO, String permissions)
            throws GeneralSecurityException, UnsupportedEncodingException, SQLException {
        boolean allowRead = "1".equals(permissions) || "2".equals(permissions);
        boolean allowModify = "2".equals(permissions);
        acDAO.create(entity, newPassword, allowRead, allowModify);
    }
}
