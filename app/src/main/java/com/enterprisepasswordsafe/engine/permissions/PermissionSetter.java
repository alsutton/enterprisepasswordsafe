package com.enterprisepasswordsafe.engine.permissions;

import com.enterprisepasswordsafe.model.AccessControledObject;
import com.enterprisepasswordsafe.model.DAORepository;
import com.enterprisepasswordsafe.model.PasswordPermission;
import com.enterprisepasswordsafe.model.Permission;
import com.enterprisepasswordsafe.model.dao.AccessControlDAOInterface;
import com.enterprisepasswordsafe.model.dao.GroupDAO;
import com.enterprisepasswordsafe.model.dao.PasswordAccessControlDAO;
import com.enterprisepasswordsafe.model.dao.UserDAO;
import com.enterprisepasswordsafe.model.persisted.AbstractActor;
import com.enterprisepasswordsafe.model.persisted.Group;
import com.enterprisepasswordsafe.model.persisted.Password;
import com.enterprisepasswordsafe.model.persisted.PasswordAccessControl;
import com.enterprisepasswordsafe.model.persisted.User;

import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.Map;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

public class PermissionSetter {

    private final User adminUser;
    private final Group adminGroup;

    private final DAORepository daoRepository;

    public PermissionSetter(DAORepository daoRepository, Group adminGroup)
            throws GeneralSecurityException {
        this.daoRepository = daoRepository;
        this.adminGroup = adminGroup;
        this.adminUser = daoRepository.getUserDAO().getAdminUser(adminGroup);
    }

    public void storeUserPermissions(final PasswordAccessControl accessControl,
                                     final Password password,
                                     final Map<? extends AbstractActor, PasswordPermission> userPermissions,
                                     final boolean overwriteExistingPermissions) {
        UserDAO userDAO = daoRepository.getUserDAO();
        PasswordAccessControlDAO acDAO = daoRepository.getPasswordAccessControlDAO();
        storeDefaultPermissions(userPermissions,
                name -> getEntity(name, userDAO, adminGroup, password),
                (entity, permission) ->
                        createAccessControlIfNeeded(
                                acDAO,
                                entity,
                                (entityUnderTest) -> hasExistingPermissions(entityUnderTest, password, acDAO, overwriteExistingPermissions),
                                () -> buildAccessControl(UserAccessControl.builder(), password, accessControl, permission)));
    }

    public void storeGroupPermissions(final PasswordAccessControl accessControl, final Password importedPassword,
                                              final Map<String, PasswordPermission> groupPermissions,
                                              final boolean overwriteExistingPermissions) {
        GroupDAO groupDAO = daoRepository.getGroupDAO();
        PasswordAccessControlDAO acDAO = daoRepository.getPasswordAccessControlDAO();
        storeDefaultPermissions(groupPermissions,
                name ->  getEntity(name, groupDAO, adminUser, importedPassword),
                (entity, permission) ->
                        createAccessControlIfNeeded(
                                acDAO,
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

    public void removePermissionsForUnknownActors(Password password,
                                                  Map<User, Permission> userPermissions,
                                                  Map<Group, Permission> groupPermissions) {
        Map<AbstractActor, PasswordAccessControl> accessControls = password.getAccessControls();

        Set<AbstractActor> actorsToRemove =
                accessControls.values().parallelStream()
                        .filter(permission -> !userPermissions.containsKey(permission.getActor()))
                        .filter(permission -> !groupPermissions.containsKey(permission.getActor()))
                        .flatMap(permission -> permission.getActor())
                        .collect(Collectors.toSet());
        actorsToRemove.stream().forEach(actor -> accessControls.remove(actor));
    }
}
