package com.enterprisepasswordsafe.engine.passwords;

import com.enterprisepasswordsafe.database.EntityWithAccessRights;
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

    private final User adminUser;
    private final Group adminGroup;

    public PasswordImporter(Group adminGroup) throws GeneralSecurityException, SQLException {
        this(PasswordDAO.getInstance(), UserDAO.getInstance(), GroupDAO.getInstance(), MembershipDAO.getInstance(),
                UserAccessControlDAO.getInstance(), GroupAccessControlDAO.getInstance(), new HierarchyNodePermissionDAO(),
                adminGroup);
    }

    // Visible for testing purposes
    PasswordImporter(PasswordDAO passwordDAO, UserDAO userDAO, GroupDAO groupDAO,
                     MembershipDAO membershipDAO, UserAccessControlDAO userAccessControlDAO,
                     GroupAccessControlDAO groupAccessControlDAO,
                     HierarchyNodePermissionDAO hierarchyNodePermissionDAO,
                     Group adminGroup) throws GeneralSecurityException, SQLException {
        this.passwordDAO = passwordDAO;
        this.userDAO = userDAO;
        this.groupDAO = groupDAO;
        this.membershipDAO = membershipDAO;
        this.userAccessControlDAO = userAccessControlDAO;
        this.groupAccessControlDAO = groupAccessControlDAO;
        this.hierarchyNodePermissionDAO = hierarchyNodePermissionDAO;
        this.adminUser = userDAO.getAdminUser(adminGroup);
        this.adminGroup = adminGroup;
    }

    public void importPassword(final User importingUser, final String parentNode, final Iterable<String> record)
            throws SQLException, GeneralSecurityException, IOException {
        Iterator<String> values = record.iterator();

        String location = getNextValueFromCSVRecordIterator(values, "Location not specified.");
        String username = getNextValueFromCSVRecordIterator(values, "Username not specified.");
        String password = getNextValueFromCSVRecordIterator(values, "Password not specified.");
        String notes = getNotesFromImport(values);
        AuditingLevel auditing = getAuditLevelFromImport(values);
        boolean recordHistory = getHistoryRecordingFromImport(values);

        Password importedPassword = passwordDAO.create(importingUser, adminGroup, username,
                password, location, notes, auditing, recordHistory, Long.MAX_VALUE,
                parentNode, null, false, 0, 0, Password.TYPE_SYSTEM, null);

        AccessControl accessControl = groupAccessControlDAO.getGac(adminGroup, importedPassword);

        importOptionalFields(accessControl, importedPassword, values);
        setRemainingDefaultAccessControls(accessControl, parentNode, importedPassword);
    }

    private void importOptionalFields(final AccessControl accessControl, final Password importedPassword,
                                      Iterator<String> values)
            throws GeneralSecurityException, IOException, SQLException {
        Map<String, String> customFields = new TreeMap<>();
        while (values.hasNext()) {
            importOptionalField(importedPassword, values.next().trim(), customFields);
        }

        importedPassword.setCustomFields(customFields);
        passwordDAO.update(importedPassword, accessControl);
    }

    private void importOptionalField(Password importedPassword, String optionalField,
                                   Map<String,String> customFields)
            throws GeneralSecurityException, UnsupportedEncodingException, SQLException {
        if (optionalField.length() < PERMISSION_HEADER_LENGTH || optionalField.charAt(2) != ':') {
            throw new GeneralSecurityException("Incorrect format " + optionalField);
        }

        if (optionalField.startsWith("CF:")) {
            importCustomField(customFields, optionalField.substring(PERMISSION_HEADER_LENGTH));
        } else {
            importPermission(importedPassword, optionalField);
        }
    }

    /**
     * Ensures that any permissions which are in the defaults for the node and have not been overridden by
     * the import data, are created.
     */
    private void setRemainingDefaultAccessControls(final AccessControl accessControl, final String parentNode,
                                          final Password importedPassword)
            throws GeneralSecurityException, SQLException {
        Map<String, PasswordPermission> userPermissions = new HashMap<>();
        Map<String, PasswordPermission> groupPermissions = new HashMap<>();

        hierarchyNodePermissionDAO.getDefaultPermissionsForNodeIncludingInherited(
                parentNode, userPermissions, groupPermissions);

        storeDefaultUserPermissions(accessControl, importedPassword, userPermissions);
        storeDefaultGroupPermissions(accessControl, importedPassword, groupPermissions);
    }

    private void storeDefaultUserPermissions(final AccessControl accessControl, final Password importedPassword,
                                             final Map<String, PasswordPermission> userPermissions)
            throws GeneralSecurityException, SQLException {
        for (Map.Entry<String, PasswordPermission> thisEntry : userPermissions.entrySet()) {
            User user = userDAO.getByIdDecrypted(thisEntry.getKey(), adminGroup);
            if (userAccessControlDAO.getUac(user, importedPassword.getId()) != null) {
                continue;
            }
            AccessControlBuilder<UserAccessControl> builder = UserAccessControl.builder();
            UserAccessControl uac = buildPermission(user, importedPassword, accessControl, thisEntry.getValue(), builder);
            if (uac != null) {
                userAccessControlDAO.write(user, builder.build());
            } else {
                Logger.getAnonymousLogger().warning("Unable to find user "+thisEntry.getKey()+" to import permission.");
            }
        }
    }

    private void storeDefaultGroupPermissions(final AccessControl accessControl, final Password importedPassword,
                                              final Map<String, PasswordPermission> groupPermissions)
            throws GeneralSecurityException, SQLException {
        for (Map.Entry<String, PasswordPermission> thisEntry : groupPermissions.entrySet()) {
            Group group = groupDAO.getByIdDecrypted(thisEntry.getKey(), adminUser);
            if (groupAccessControlDAO.getGac(group, importedPassword) != null) {
                continue;
            }
            AccessControlBuilder<GroupAccessControl> builder = GroupAccessControl.builder();
            GroupAccessControl gac = buildPermission(group, importedPassword, accessControl, thisEntry.getValue(), builder);
            if (gac != null) {
                groupAccessControlDAO.write(group, gac);
            } else {
                Logger.getAnonymousLogger().warning("Unable to find group "+thisEntry.getKey()+" to import permission.");
            }
        }
    }

    private <T extends AccessControl> T buildPermission(EntityWithAccessRights entity, Password importedPassword,
        AccessControl accessControl, PasswordPermission permission, AccessControlBuilder<T> accessControlBuilder) {
        if (entity == null || entity.getId() == null) {
            return null;
        }
        accessControlBuilder.withAccessorId(entity.getId())
                .withItemId(importedPassword.getId())
                .withReadKey(accessControl.getReadKey());
        if (permission == PasswordPermission.MODIFY) {
            accessControlBuilder.withModifyKey(accessControl.getModifyKey());
        }
        return accessControlBuilder.build();
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
        return notes.replaceAll("<br>", "\n").replaceAll("<br/>", "\n");
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
     * @param permission  The permission being imported.
     * @throws SQLException                 Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException     Thrown if there is a problem encrypting/decrypting the permissions
     * @throws UnsupportedEncodingException Thrown if there is a problem decoding text.
     */

    private void importPermission(final Password thePassword, final String permission)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        char permissionType = permission.charAt(1);
        if (permissionType != 'M' && permissionType != 'V') {
            return;
        }

        // Get the name of the object the permission is for
        String objectName = permission.substring(PERMISSION_HEADER_LENGTH);
        char objectType = permission.charAt(0);
        if (objectType == 'U' || objectType == 'u') {
            createUserPermission(thePassword, objectName, permissionType == 'M');
        } else if (objectType == 'G' || objectType == 'g') {
            createGroupPermission(thePassword, objectName, permissionType == 'M');
        }
    }

    private void createUserPermission(final Password thePassword, final String objectName, final boolean allowModify)
            throws GeneralSecurityException, UnsupportedEncodingException, SQLException {
        User theUser = userDAO.getByName(objectName);
        if (theUser == null) {
            throw new GeneralSecurityException("User " + objectName + " does not exist");
        }
        theUser.decryptAdminAccessKey(adminGroup);
        PasswordPermission permission = allowModify ? PasswordPermission.MODIFY : PasswordPermission.READ;
        userAccessControlDAO.create(theUser, thePassword, permission);
    }

    private void createGroupPermission(final Password thePassword, final String objectName, final boolean allowModify)
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