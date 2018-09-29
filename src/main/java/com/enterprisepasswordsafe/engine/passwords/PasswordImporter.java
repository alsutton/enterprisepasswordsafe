package com.enterprisepasswordsafe.engine.passwords;

import com.enterprisepasswordsafe.engine.database.*;
import org.apache.commons.csv.CSVRecord;

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

    private PasswordDAO passwordDAO;

    public PasswordImporter() {
        passwordDAO = PasswordDAO.getInstance();
    }

    public void importPassword(final User theImporter, final Group adminGroup,
                               final String parentNode, final CSVRecord record)
            throws SQLException, GeneralSecurityException, IOException {

        Iterator<String> values = record.iterator();

        String location = getNextValueFromCSVRecordIterator(values, "Location not specified.");
        String username = getNextValueFromCSVRecordIterator(values, "Username not specified.");
        String password = getNextValueFromCSVRecordIterator(values, "Password not specified.");
        String notes = getNotesFromImport(values);
        int auditing = getAuditLevelFromImport(values);
        boolean recordHistory = getHistoryRecordingFromImport(values);

        Password importedPassword = passwordDAO.create(theImporter, adminGroup, username,
                password, location, notes, auditing, recordHistory, Long.MAX_VALUE,
                parentNode, null, false, 0, 0, Password.TYPE_SYSTEM, null);

        User adminUser = UserDAO.getInstance().getAdminUser(adminGroup);
        AccessControl accessControl = GroupAccessControlDAO.getInstance().getGac(adminGroup, importedPassword);

        importCustomFields(adminUser, adminGroup, accessControl, importedPassword, values);

        importAccessControls(adminUser, adminGroup, accessControl, parentNode, importedPassword, values);
    }

    private void importCustomFields(final User adminUser, final Group adminGroup, final AccessControl accessControl,
                                    final Password importedPassword, Iterator<String> values )
            throws GeneralSecurityException, IOException, SQLException  {
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
                                      final Iterator<String> importedPermissions )
            throws GeneralSecurityException, UnsupportedEncodingException, SQLException {
        Map<String,String> userPermissions = new HashMap<>();
        Map<String,String> groupPermissions = new HashMap<>();

        new HierarchyNodePermissionDAO().getDefaultPermissionsForNodeIncludingInherited(
                parentNode, userPermissions, groupPermissions);

        updateWithImportedPermissions(userPermissions, groupPermissions, importedPermissions);

        storeImportedUserPermissions(adminGroup, accessControl, importedPassword, userPermissions);
        storeImportedGroupPermissions(adminUser, accessControl, importedPassword, groupPermissions);
    }

    private void updateWithImportedPermissions(Map<String,String> userPermissions, Map<String,String> groupPermissions,
                                               Iterator<String> importedPermissions) {
        UserDAO userDAO = UserDAO.getInstance();
        GroupDAO groupDAO = GroupDAO.getInstance();

        while(importedPermissions.hasNext()) {
            String permission = importedPermissions.next().trim();
            if(permission.isEmpty() || permission.length() < 4) {
                continue;
            }

            String actorName = permission.substring(3);
            try {
                switch (permission.charAt(0)) {
                    case 'U':
                        User user = userDAO.getByName(actorName);
                        importPermission(userPermissions, user.getId(), permission);
                        break;
                    case 'G':
                        Group group = groupDAO.getByName(actorName);
                        importPermission(groupPermissions, group.getGroupId(), permission);
                        break;
                    default:
                        Logger.getAnonymousLogger().log(Level.SEVERE, "Unrecognised permission on import : " + permission);
                        break;
                }
            } catch(Exception e) {
                Logger.getAnonymousLogger().log(Level.SEVERE, "Problem importing permission : " +permission);
            }
        }
    }

    private void importPermission(Map<String, String> permissionMap, String id, String permission) {
        switch(permission.charAt(1)) {
            case 'V':
                permissionMap.put(id, AccessControl.READ_PERMISSION);
                break;
            case 'M':
                permissionMap.put(id, AccessControl.MODIFY_PERMISSION);
                break;
        }
    }

    private void storeImportedUserPermissions(final Group adminGroup, final AccessControl accessControl,
                                              final Password importedPassword, final Map<String,String> userPermissions)
            throws GeneralSecurityException, UnsupportedEncodingException, SQLException {
        final UserDAO uDAO = UserDAO.getInstance();
        final UserAccessControlDAO uacDAO = UserAccessControlDAO.getInstance();

        for(Map.Entry<String,String> thisEntry : userPermissions.entrySet()) {
            User user = uDAO.getByIdDecrypted(thisEntry.getKey(), adminGroup);
            UserAccessControl uac = new UserAccessControl();
            uac.setAccessorId(user.getId());
            uac.setItemId(importedPassword.getId());
            uac.setReadKey(accessControl.getReadKey());
            if(thisEntry.getValue().equals("2")) {
                uac.setModifyKey(accessControl.getModifyKey());
            }
            uacDAO.write(uac, user);
        }
    }

    private void storeImportedGroupPermissions(final User adminUser, final AccessControl accessControl,
                                               final Password importedPassword, final Map<String,String> groupPermissions)
            throws GeneralSecurityException, UnsupportedEncodingException, SQLException {
        final GroupDAO groupDAO = GroupDAO.getInstance();
        final GroupAccessControlDAO groupAccessControlDAO = GroupAccessControlDAO.getInstance();

        for(Map.Entry<String,String> thisEntry : groupPermissions.entrySet()) {
            Group group = groupDAO.getByIdDecrypted(thisEntry.getKey(), adminUser);
            GroupAccessControl gac = new GroupAccessControl();
            gac.setAccessorId(group.getGroupId());
            gac.setItemId(importedPassword.getId());
            gac.setReadKey(accessControl.getReadKey());
            if(thisEntry.getValue().equals("2")) {
                gac.setModifyKey(accessControl.getModifyKey());
            }
            groupAccessControlDAO.write(group, gac);
        }
    }

    private String getNextValueFromCSVRecordIterator(final Iterator<String> iterator, final String error )
            throws GeneralSecurityException {
        if (!iterator.hasNext()) {
            throw new GeneralSecurityException(error);
        }
        return iterator.next().trim();

    }

    private String getNotesFromImport(Iterator<String> values) {
        if(!values.hasNext()) {
            return "";
        }

        String notes = values.next().trim();
        notes = notes.replaceAll("<br>", "\n");
        notes = notes.replaceAll("<br/>", "\n");
        return notes;
    }

    private int getAuditLevelFromImport(Iterator<String> values)
            throws GeneralSecurityException {
        if (!values.hasNext()) {
            return Password.AUDITING_FULL;
        }

        String audit = values.next().trim().toLowerCase();
        if (audit.length() == 0 || audit.equals("full")) {
            return Password.AUDITING_FULL;
        }
        if (audit.equals("log")) {
            return Password.AUDITING_LOG_ONLY;
        }
        if (audit.equals("none")) {
            return Password.AUDITING_NONE;
        }

        throw new GeneralSecurityException( "Invalid auditing value specified ("+audit+").");
    }

    private boolean getHistoryRecordingFromImport(Iterator<String> values) {
        if(!values.hasNext()) {
            return true;
        }

        String history = values.next().trim().toLowerCase();
        return Boolean.valueOf(history);
    }


    /**
     * Handles the import of a custom field permission.
     *
     * @param customFields The map of custom fields.
     * @param customField The defintiion of the custom field
     */

    private void importCustomField(final Map<String,String> customFields, final String customField) {
        String fieldName = customField.trim();
        String fieldValue = "";
        int equalsIdx = fieldName.indexOf('=');
        if(equalsIdx != -1) {
            fieldValue = fieldName.substring(equalsIdx+1);
            fieldName = fieldName.substring(0, equalsIdx);
        }
        customFields.put(fieldName, fieldValue);
    }

    /**
     * Handles the import of an access permission.
     *
     * @param thePassword The password being imported.
     * @param adminUser The administrator user doing the import.
     * @param adminGroup The admin group for permission handling.
     * @param permission The permission being imported.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem encrypting/decrypting the permissions
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
        User theUser = UserDAO.getInstance().getByName(objectName);
        if (theUser == null) {
            throw new GeneralSecurityException("User " + objectName + " does not exist");
        }
        theUser.decryptAdminAccessKey(adminGroup);
        UserAccessControlDAO.getInstance().create(theUser, thePassword, true, allowModify);

    }

    private void createGroupPermission(final Password thePassword, final User adminUser,
                                  final String objectName, final boolean allowModify)
            throws GeneralSecurityException, UnsupportedEncodingException, SQLException {
        Group theGroup = GroupDAO.getInstance().getByName(objectName);
        if (theGroup == null) {
            throw new GeneralSecurityException("Group " + objectName+ " does not exist");
        }
        Membership membership = MembershipDAO.getInstance().getMembership(adminUser, theGroup);
        theGroup.updateAccessKey(membership);
        GroupAccessControlDAO.getInstance().create(theGroup, thePassword, true, allowModify);
    }

}
