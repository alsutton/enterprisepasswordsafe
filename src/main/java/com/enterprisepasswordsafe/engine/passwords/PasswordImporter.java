package com.enterprisepasswordsafe.engine.passwords;

import com.enterprisepasswordsafe.database.Group;
import com.enterprisepasswordsafe.database.GroupAccessControlDAO;
import com.enterprisepasswordsafe.database.GroupDAO;
import com.enterprisepasswordsafe.database.HierarchyNodePermissionDAO;
import com.enterprisepasswordsafe.database.Membership;
import com.enterprisepasswordsafe.database.MembershipDAO;
import com.enterprisepasswordsafe.database.Password;
import com.enterprisepasswordsafe.database.PasswordDAO;
import com.enterprisepasswordsafe.database.User;
import com.enterprisepasswordsafe.database.UserAccessControlDAO;
import com.enterprisepasswordsafe.database.UserDAO;
import com.enterprisepasswordsafe.engine.accesscontrol.AccessControl;
import com.enterprisepasswordsafe.engine.accesscontrol.AccessControlBuilder;
import com.enterprisepasswordsafe.engine.accesscontrol.GroupAccessControl;
import com.enterprisepasswordsafe.engine.accesscontrol.PasswordPermission;
import com.enterprisepasswordsafe.engine.accesscontrol.UserAccessControl;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class PasswordImporter {

    /**
     * The length of a permission header on an import line.
     */

    private static final int PERMISSION_HEADER_LENGTH = 3;

    private final PasswordDAO passwordDAO;
    private final UserDAO userDAO;
    private final GroupDAO groupDAO;
    private final MembershipDAO membershipDAO;
    private final UserAccessControlDAO userAccessControlDAO;
    private final GroupAccessControlDAO groupAccessControlDAO;
    private final HierarchyNodePermissionDAO hierarchyNodePermissionDAO;

    public PasswordImporter() {
        passwordDAO = PasswordDAO.getInstance();
        userDAO = UserDAO.getInstance();
        groupDAO = GroupDAO.getInstance();
        membershipDAO = MembershipDAO.getInstance();
        userAccessControlDAO = UserAccessControlDAO.getInstance();
        groupAccessControlDAO = GroupAccessControlDAO.getInstance();
        hierarchyNodePermissionDAO = new HierarchyNodePermissionDAO();
    }

    // Visible for testing purposes
    PasswordImporter(PasswordDAO passwordDAO, UserDAO userDAO, GroupDAO groupDAO,
                     MembershipDAO membershipDAO,
                     UserAccessControlDAO userAccessControlDAO,
                     GroupAccessControlDAO groupAccessControlDAO,
                     HierarchyNodePermissionDAO hierarchyNodePermissionDAO) {
        this.passwordDAO = passwordDAO;
        this.userDAO = userDAO;
        this.groupDAO = groupDAO;
        this.membershipDAO = membershipDAO;
        this.userAccessControlDAO = userAccessControlDAO;
        this.groupAccessControlDAO = groupAccessControlDAO;
        this.hierarchyNodePermissionDAO = hierarchyNodePermissionDAO;
    }

    public void importPassword(final User theImporter, final Group adminGroup,
                               final String parentNode, final Iterable<String> record)
            throws SQLException, GeneralSecurityException, IOException {
        Iterator<String> values = record.iterator();

        String location = getNextValueFromCSVRecordIterator(values, "Location not specified.");
        String username = getNextValueFromCSVRecordIterator(values, "Username not specified.");
        String password = getNextValueFromCSVRecordIterator(values, "Password not specified.");
        String notes = getNotesFromImport(values);
        AuditingLevel auditing = getAuditLevelFromImport(values);
        boolean recordHistory = getHistoryRecordingFromImport(values);

        Password importedPassword = passwordDAO.create(theImporter, adminGroup, username,
                password, location, notes, auditing, recordHistory, Long.MAX_VALUE,
                parentNode, null, false, 0, 0, Password.TYPE_SYSTEM, null);

        User adminUser = userDAO.getAdminUser(adminGroup);
        AccessControl accessControl = groupAccessControlDAO.getGac(adminGroup, importedPassword);

        importCustomFields(adminUser, adminGroup, accessControl, importedPassword, values);

        importAccessControls(adminUser, adminGroup, accessControl, parentNode, importedPassword, values);
    }

    private void importCustomFields(final User adminUser, final Group adminGroup, final AccessControl accessControl,
                                    final Password importedPassword, Iterator<String> values)
            throws GeneralSecurityException, IOException, SQLException {
        Map<String, String> customFields = new TreeMap<>();
        while (values.hasNext()) {
            String nextToken = values.next().trim();
            if (nextToken.length() < PERMISSION_HEADER_LENGTH || nextToken.charAt(2) != ':') {
                throw new GeneralSecurityException("Incorrect format " + nextToken);
            }

            if (nextToken.startsWith("CF:")) {
                importCustomField(customFields, nextToken.substring(PERMISSION_HEADER_LENGTH));
            } else {
                importPermission(importedPassword, adminUser, adminGroup, nextToken);
            }
        }

        importedPassword.setCustomFields(customFields);
        passwordDAO.update(importedPassword, accessControl);
    }

    private void importAccessControls(final User adminUser, final Group adminGroup, final AccessControl accessControl,
                                      final String parentNode, final Password importedPassword,
                                      final Iterator<String> importedPermissions)
            throws GeneralSecurityException, SQLException {
        Map<String, PasswordPermission> userPermissions = new HashMap<>();
        Map<String, PasswordPermission> groupPermissions = new HashMap<>();

        hierarchyNodePermissionDAO.getDefaultPermissionsForNodeIncludingInherited(
                parentNode, userPermissions, groupPermissions);

        updateWithImportedPermissions(userPermissions, groupPermissions, importedPermissions);

        storeImportedUserPermissions(adminGroup, accessControl, importedPassword, userPermissions);
        storeImportedGroupPermissions(adminUser, accessControl, importedPassword, groupPermissions);
    }

    private void updateWithImportedPermissions(Map<String, PasswordPermission> userPermissions,
                                               Map<String, PasswordPermission> groupPermissions,
                                               Iterator<String> importedPermissions) {
        while (importedPermissions.hasNext()) {
            String permission = importedPermissions.next().trim();
            if (permission.isEmpty() || permission.length() < 4) {
                continue;
            }

            importPermission(userPermissions, groupPermissions, permission);
        }
    }

    private void importPermission(Map<String, PasswordPermission> userPermissions,
                                  Map<String, PasswordPermission> groupPermissions,
                                  String permission) {
        String actorName = permission.substring(3);
        try {
            switch (permission.charAt(0)) {
                case 'U':
                    User user = userDAO.getByName(actorName);
                    userPermissions.put(user.getId(), PasswordPermission.fromRepresentation(permission));
                    break;
                case 'G':
                    Group group = groupDAO.getByName(actorName);
                    groupPermissions.put(group.getGroupId(), PasswordPermission.fromRepresentation(permission));
                    break;
                default:
                    Logger.getAnonymousLogger().log(Level.SEVERE, "Unrecognised permission on import : " + permission);
                    break;
            }
        } catch (Exception e) {
            Logger.getAnonymousLogger().log(Level.SEVERE, "Problem importing permission : " + permission);
        }
    }

    private void storeImportedUserPermissions(final Group adminGroup, final AccessControl accessControl,
                                              final Password importedPassword,
                                              final Map<String, PasswordPermission> userPermissions)
            throws GeneralSecurityException, SQLException {
        for (Map.Entry<String, PasswordPermission> thisEntry : userPermissions.entrySet()) {
            User user = userDAO.getByIdDecrypted(thisEntry.getKey(), adminGroup);
            if (user == null || user.getId() == null) {
                Logger.getAnonymousLogger().warning("Unable to find user " + thisEntry.getKey() + " to import permission.");
                continue;
            }
            AccessControlBuilder<UserAccessControl> builder = UserAccessControl.builder();
            buildPermission(user.getId(), importedPassword, accessControl, thisEntry.getValue(), builder);
            userAccessControlDAO.write(builder.build(), user);
        }
    }

    private void storeImportedGroupPermissions(final User adminUser, final AccessControl accessControl,
                                               final Password importedPassword,
                                               final Map<String, PasswordPermission> groupPermissions)
            throws GeneralSecurityException, SQLException {
        for (Map.Entry<String, PasswordPermission> thisEntry : groupPermissions.entrySet()) {
            Group group = groupDAO.getByIdDecrypted(thisEntry.getKey(), adminUser);
            AccessControlBuilder<GroupAccessControl> builder = GroupAccessControl.builder();
            buildPermission(group.getId(), importedPassword, accessControl, thisEntry.getValue(), builder);
            groupAccessControlDAO.write(group, builder.build());
        }
    }

    private void buildPermission(String accessorId, Password importedPassword, AccessControl accessControl,
                                 PasswordPermission permission, AccessControlBuilder<?> accessControlBuilder) {
        accessControlBuilder.withAccessorId(accessorId)
                .withItemId(importedPassword.getId())
                .withReadKey(accessControl.getReadKey());
        if (permission == PasswordPermission.MODIFY) {
            accessControlBuilder.withModifyKey(accessControl.getModifyKey());
        }
    }

    private String getNextValueFromCSVRecordIterator(final Iterator<String> iterator, final String error)
            throws GeneralSecurityException {
        if (!iterator.hasNext()) {
            throw new GeneralSecurityException(error);
        }
        return iterator.next().trim();
    }

    private String getNotesFromImport(Iterator<String> values) {
        if (!values.hasNext()) {
            return "";
        }

        String notes = values.next().trim();
        notes = notes.replaceAll("<br>", "\n");
        notes = notes.replaceAll("<br/>", "\n");
        return notes;
    }

    private AuditingLevel getAuditLevelFromImport(Iterator<String> values)
            throws GeneralSecurityException {
        if (!values.hasNext()) {
            return AuditingLevel.FULL;
        }

        String audit = values.next().trim();
        AuditingLevel auditingLevel = AuditingLevel.fromRepresentation(audit);
        if (auditingLevel == null) {
            throw new GeneralSecurityException("Invalid auditing value specified (" + audit + ").");
        }
        return auditingLevel;
    }

    private boolean getHistoryRecordingFromImport(Iterator<String> values) {
        if (!values.hasNext()) {
            return true;
        }

        return Boolean.parseBoolean(values.next().trim().toLowerCase());
    }

    /**
     * Handles the import of a custom field permission.
     *
     * @param customFields The map of custom fields.
     * @param customField  The defintiion of the custom field
     */

    private void importCustomField(final Map<String, String> customFields, final String customField) {
        String fieldName = customField.trim();
        String fieldValue = "";
        int equalsIdx = fieldName.indexOf('=');
        if (equalsIdx != -1) {
            fieldValue = fieldName.substring(equalsIdx + 1);
            fieldName = fieldName.substring(0, equalsIdx);
        }
        customFields.put(fieldName, fieldValue);
    }

    /**
     * Handles the import of an access permission.
     *
     * @param thePassword The password being imported.
     * @param adminUser   The administrator user doing the import.
     * @param adminGroup  The admin group for permission handling.
     * @param permission  The permission being imported.
     * @throws SQLException                 Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException     Thrown if there is a problem encrypting/decrypting the permissions
     * @throws UnsupportedEncodingException Thrown if there is a problem decoding text.
     */

    private void importPermission(final Password thePassword, final User adminUser,
                                  final Group adminGroup, final String permission)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        char permissionType = permission.charAt(1);
        boolean allowModify;
        if (permissionType == 'M') {
            allowModify = true;
        } else if (permissionType == 'V') {
            allowModify = false;
        } else {
            return;
        }

        // Get the name of the object the permission is for
        String objectName = permission.substring(PERMISSION_HEADER_LENGTH);
        char objectType = permission.charAt(0);
        if (objectType == 'U' || objectType == 'u') {
            createUserPermission(thePassword, adminGroup, objectName, allowModify);
        } else if (objectType == 'G' || objectType == 'g') {
            createGroupPermission(thePassword, adminUser, objectName, allowModify);
        }
    }

    private void createUserPermission(final Password thePassword, final Group adminGroup,
                                      final String objectName, final boolean allowModify)
            throws GeneralSecurityException, UnsupportedEncodingException, SQLException {
        User theUser = userDAO.getByName(objectName);
        if (theUser == null) {
            throw new GeneralSecurityException("User " + objectName + " does not exist");
        }
        theUser.decryptAdminAccessKey(adminGroup);
        PasswordPermission permission = allowModify ? PasswordPermission.MODIFY : PasswordPermission.READ;
        userAccessControlDAO.create(theUser, thePassword, permission);
    }

    private void createGroupPermission(final Password thePassword, final User adminUser,
                                       final String objectName, final boolean allowModify)
            throws GeneralSecurityException, SQLException {
        Group theGroup = groupDAO.getByName(objectName);
        if (theGroup == null) {
            throw new GeneralSecurityException("Group " + objectName + " does not exist");
        }
        Membership membership = membershipDAO.getMembership(adminUser, theGroup);
        theGroup.updateAccessKey(membership);
        PasswordPermission permission = allowModify ? PasswordPermission.MODIFY : PasswordPermission.READ;
        groupAccessControlDAO.create(theGroup, thePassword, permission);
    }

}
