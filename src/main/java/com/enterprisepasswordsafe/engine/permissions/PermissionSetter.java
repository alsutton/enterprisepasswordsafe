package com.enterprisepasswordsafe.engine.permissions;

import com.enterprisepasswordsafe.database.AccessControledObject;
import com.enterprisepasswordsafe.database.EntityWithAccessRights;
import com.enterprisepasswordsafe.database.EntityWithAccessRightsDAO;
import com.enterprisepasswordsafe.database.Group;
import com.enterprisepasswordsafe.database.GroupAccessControlDAO;
import com.enterprisepasswordsafe.database.GroupDAO;
import com.enterprisepasswordsafe.database.Password;
import com.enterprisepasswordsafe.database.User;
import com.enterprisepasswordsafe.database.UserAccessControlDAO;
import com.enterprisepasswordsafe.database.UserDAO;
import com.enterprisepasswordsafe.database.schema.AccessControlDAOInterface;
import com.enterprisepasswordsafe.engine.AccessControlDecryptor;
import com.enterprisepasswordsafe.engine.accesscontrol.AccessControl;
import com.enterprisepasswordsafe.engine.accesscontrol.AccessControlBuilder;
import com.enterprisepasswordsafe.engine.accesscontrol.GroupAccessControl;
import com.enterprisepasswordsafe.engine.accesscontrol.PasswordPermission;
import com.enterprisepasswordsafe.engine.accesscontrol.UserAccessControl;

import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;

public class PermissionSetter {

    private final User adminUser;
    private final Group adminGroup;

    private final UserDAO userDAO;
    private final GroupDAO groupDAO;

    private final UserAccessControlDAO userAccessControlDAO;
    private final GroupAccessControlDAO groupAccessControlDAO;

    public PermissionSetter(UserDAO userDAO, GroupDAO groupDAO, UserAccessControlDAO userAccessControlDAO,
                     GroupAccessControlDAO groupAccessControlDAO, Group adminGroup)
            throws GeneralSecurityException, SQLException {
        this.userDAO = userDAO;
        this.groupDAO = groupDAO;
        this.userAccessControlDAO = userAccessControlDAO;
        this.groupAccessControlDAO = groupAccessControlDAO;
        this.adminUser = userDAO.getAdminUser(adminGroup);
        this.adminGroup = adminGroup;
    }

    public void storeUserPermissions(final AccessControl accessControl, final Password importedPassword,
                                             final Map<String, PasswordPermission> userPermissions,
                                             final boolean overwriteExistingPermissions) {
        storeDefaultPermissions(userPermissions,
                name -> getEntity(name, userDAO, adminGroup, importedPassword),
                (entity, permission) ->
                        createAccessControlIfNeeded(
                                userAccessControlDAO,
                                entity,
                                (entityUnderTest) -> hasExistingPermissions(entityUnderTest, importedPassword, userAccessControlDAO, overwriteExistingPermissions),
                                () -> buildAccessControl(UserAccessControl.builder(), importedPassword, accessControl, permission)));
    }

    public void storeGroupPermissions(final AccessControl accessControl, final Password importedPassword,
                                              final Map<String, PasswordPermission> groupPermissions,
                                              final boolean overwriteExistingPermissions) {
        storeDefaultPermissions(groupPermissions,
                name ->  getEntity(name, groupDAO, adminUser, importedPassword),
                (entity, permission) ->
                        createAccessControlIfNeeded(
                                groupAccessControlDAO,
                                entity,
                                (entityUnderTest) -> hasExistingPermissions(entityUnderTest, importedPassword, groupAccessControlDAO, overwriteExistingPermissions),
                                () -> buildAccessControl(GroupAccessControl.builder(), importedPassword, accessControl, permission)));
    }

    private <T extends EntityWithAccessRights, AC extends AccessControl> void
    createAccessControlIfNeeded(AccessControlDAOInterface<T, AC> accessControlDao,
                                T entity,
                                Predicate<T> hasExistingPermission,
                                Supplier<AC> accessControlSupplier) {
        try {
            if(!hasExistingPermission.test(entity)) {
                createAccessControl(accessControlDao, entity, accessControlSupplier);
            }
        } catch (SQLException | GeneralSecurityException e) {
            Logger.getAnonymousLogger().log(Level.SEVERE, "Unable to store group access control", e);
        }
    }

    private <T extends EntityWithAccessRights, AC extends AccessControl> boolean
        hasExistingPermissions(T entity, AccessControledObject importedObject, AccessControlDAOInterface<T, AC> dao,
                               boolean override) {
        try {
            return override || dao.get(entity, importedObject) != null;
        } catch (SQLException | GeneralSecurityException e) {
            Logger.getAnonymousLogger().log(Level.SEVERE, "Unable to check permission", e);
            return true;
        }
    }

    private <T extends EntityWithAccessRights, AC extends AccessControl> void
    createAccessControl(AccessControlDAOInterface<T, AC> accessControlDao, T entity,
                                Supplier<AC> accessControlSupplier)
            throws GeneralSecurityException, SQLException {
        accessControlDao.write(entity, accessControlSupplier.get());
    }

    private <AC extends AccessControl> AC buildAccessControl(AccessControlBuilder<AC> builder,
                                                             AccessControledObject accessControledObject, AccessControl existingAccessControl,
                                                             PasswordPermission permission) {
        builder = builder.withItemId(accessControledObject.getId()).withReadKey(existingAccessControl.getReadKey());
        if(permission.equals(PasswordPermission.MODIFY)) {
            builder = builder.withModifyKey(existingAccessControl.getModifyKey());
        }
        return builder.build();
    }

    private <T extends EntityWithAccessRights>
    void storeDefaultPermissions(Map<String, PasswordPermission> permissions,
                                 Function<String, T> entitySupplier,
                                 BiConsumer<T, PasswordPermission> accessControlCreator) {
        for (Map.Entry<String, PasswordPermission> thisEntry : permissions.entrySet()) {
            T entity = entitySupplier.apply(thisEntry.getKey());
            accessControlCreator.accept(entity, thisEntry.getValue());
        }
    }

    private <T extends EntityWithAccessRights, D extends AccessControlDecryptor> T
    getEntity(String id, EntityWithAccessRightsDAO<T,D> dao, D decrypter, AccessControledObject importedObject) {
        try {
            T entity = dao.getByIdDecrypted(id, decrypter);
            if (entity == null || entity.getId() == null) {
                Logger.getAnonymousLogger().warning("Unable to find " +
                        id + " when importing" + importedObject.toString());
                return null;
            }
            return entity;
        } catch (SQLException | GeneralSecurityException e) {
            Logger.getAnonymousLogger().warning("Error fetching " + id + " from  " + dao.getClass());
            return null;
        }
    }

}
