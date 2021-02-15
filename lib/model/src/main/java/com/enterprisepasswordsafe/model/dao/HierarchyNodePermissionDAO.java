package com.enterprisepasswordsafe.model.dao;

import com.enterprisepasswordsafe.model.DAORepository;
import com.enterprisepasswordsafe.model.Permission;
import com.enterprisepasswordsafe.model.persisted.AbstractActor;
import com.enterprisepasswordsafe.model.persisted.Group;
import com.enterprisepasswordsafe.model.persisted.HierarchyNode;
import com.enterprisepasswordsafe.model.persisted.HierarchyNodePermission;
import com.enterprisepasswordsafe.model.persisted.User;

import javax.persistence.EntityManager;
import javax.persistence.TypedQuery;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Stream;

public class HierarchyNodePermissionDAO
    extends JPADAOBase<HierarchyNodePermission> {

    public HierarchyNodePermissionDAO(DAORepository daoRepository, EntityManager entityManager) {
        super(daoRepository, entityManager, HierarchyNodePermission.class);
    }

    /**
     * Gets the default password permissions for a hierarchy node.
     *
     * @param node The node we're getting the defaults for.
     * @param userPermMap The map of user permissions.
     * @param groupPermMap The map of group permissions.
     */

    public void getDefaultPermissionsForNode(final HierarchyNode node,
                                             final Map<AbstractActor, Permission> userPermMap,
                                             final Map<AbstractActor, Permission> groupPermMap) {
        splitPermissionMap(getPermissionStreamForNode(node), userPermMap, groupPermMap);
    }

    /**
     * Get the default permissions for a user or group.
     *
     * @param node The node to get the default permission for
     * @param actor The actor to get the default permission for.
     *
     * @return The default permission for the user.
     */

    public HierarchyNodePermission getDefaultPermission(final HierarchyNode node, final AbstractActor actor) {
        return node.getDefaultPermissions().get(actor);
    }

    /**
     * Gets the default password permissions for a hierarchy node including permissions inherited
     * from an ancestor.
     *
     * @param node The node to get the permissions for
     * @param userPermMap The map of user permissions.
     * @param groupPermMap The map of group permissions.
     */

    public void getDefaultPermissionsForNodeIncludingInherited(final HierarchyNode node,
                                                               final Map<AbstractActor,Permission> userPermMap,
                                                               final Map<AbstractActor,Permission> groupPermMap) {
        Map<AbstractActor, HierarchyNodePermission> permissions = Map.copyOf(node.getDefaultPermissions());

        HierarchyNode currentAncestor = node.getParent();
        while(currentAncestor != null) {
            addMissingPermissionsFromNode(currentAncestor, permissions);
            currentAncestor = currentAncestor.getParent();
        }

        splitPermissionMap(permissions.values().stream(), userPermMap, groupPermMap);
    }

    private void addMissingPermissionsFromNode(final HierarchyNode node,
            final Map<AbstractActor, HierarchyNodePermission> permissions) {
        getPermissionStreamForNode(node)
            .filter(permission -> isPermissionUnknown(permission.getActor(), permissions))
            .forEach(permission -> permissions.put(permission.getActor(), permission));
    }

    private Stream<HierarchyNodePermission> getPermissionStreamForNode(HierarchyNode node) {
        if( node == null )
            return Stream.empty();

        TypedQuery<HierarchyNodePermission> query =
                entityManager.createQuery(
                                "SELECT h FROM HierarchyNodePermission h WHERE h.node = :node",
                                HierarchyNodePermission.class);
        query.setParameter("node", node);
        return query.getResultStream();
    }

    private boolean isPermissionUnknown(AbstractActor actor, Map<AbstractActor, HierarchyNodePermission> permissionMap) {
        HierarchyNodePermission permission = permissionMap.get(actor);
        return permission == null || permission.getPermission() == Permission.APPLY_DEFAULT;
    }

    private void splitPermissionMap(final Stream<HierarchyNodePermission> permissionStream,
                                    final Map<AbstractActor,Permission> userPermMap,
                                    final Map<AbstractActor,Permission> groupPermMap) {
        permissionStream.parallel().forEach(hierarchyNodePermission -> {
                    Permission permission = hierarchyNodePermission.getPermission();
                    AbstractActor actor = hierarchyNodePermission.getActor();
                    if(actor instanceof User) {
                        synchronized (userPermMap) {
                            userPermMap.put(actor, permission);
                        }
                    } else if (actor instanceof Group) {
                        synchronized (groupPermMap) {
                            groupPermMap.put(actor, permission);
                        }
                    } else {
                        Logger.getAnonymousLogger()
                                .log(Level.SEVERE, "Unknown actor "+actor.getClass().getCanonicalName());
                    }
                });
    }

    /**
     * Sets the default password permissions for a hierarchy node.
     *
     * @param node The node to set the permissions for
     * @param userPermMap The map of user permissions.
     * @param groupPermMap The map of group permissions.
     */

    public void setDefaultPermissionsForNode(final HierarchyNode node,
                                             final Map<Long,Permission> userPermMap,
                                             final Map<Long,Permission> groupPermMap) {
        node.getDefaultPermissions().clear();

        UserDAO userDAO = daoRepository.getUserDAO();
        for(Map.Entry<Long,Permission> userPermission : userPermMap.entrySet()) {
            User user = userDAO.getById(userPermission.getKey());
            HierarchyNodePermission hierarchyNodePermission =
                    new HierarchyNodePermission(user, userPermission.getValue(), node);
            store(hierarchyNodePermission);
        }

        GroupDAO groupDAO = daoRepository.getGroupDAO();
        for(Map.Entry<Long,Permission> groupPermission : groupPermMap.entrySet()) {
            Group group = groupDAO.getById(groupPermission.getKey());
            HierarchyNodePermission hierarchyNodePermission =
                    new HierarchyNodePermission(group, groupPermission.getValue(), node);
            store(hierarchyNodePermission);
        }
    }
}
