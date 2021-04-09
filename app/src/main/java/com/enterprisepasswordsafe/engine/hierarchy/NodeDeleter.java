package com.enterprisepasswordsafe.engine.hierarchy;

import com.enterprisepasswordsafe.logging.LogStore;
import com.enterprisepasswordsafe.model.DAORepository;
import com.enterprisepasswordsafe.model.LogEventClass;
import com.enterprisepasswordsafe.model.dao.HierarchyNodeDAO;
import com.enterprisepasswordsafe.model.persisted.HierarchyNode;
import com.enterprisepasswordsafe.model.persisted.Password;
import com.enterprisepasswordsafe.model.persisted.PasswordAccessControl;
import com.enterprisepasswordsafe.model.persisted.User;

import java.security.GeneralSecurityException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class NodeDeleter {

    private final DAORepository daoRepository;
    private final LogStore logStore;

    public NodeDeleter(final DAORepository daoRepository, LogStore logStore) {
        this.daoRepository = daoRepository;
        this.logStore = logStore;
    }

    public void deleteNodes(final User deletingUser, final HierarchyNode parent, final String[] nodes) {
        validateSelectedNodes(deletingUser, parent, nodes);
        deleteSpecifiedNodes(deletingUser, parent, nodes);
    }

    private void validateSelectedNodes(User deletingUser, HierarchyNode parent, String[] nodes)  {
        HierarchyNodeDAO hierarchyNodeDAO = daoRepository.getHierarchyNodeDAO();

        for (String thisNodeId : nodes) {
            if (thisNodeId == null) {
                continue;
            }

            if (thisNodeId.startsWith("p_")) {
                Password password =
                        parent.getPasswords().get(Long.parseLong(thisNodeId.substring(2)));
                if(isDeletionBlocked(deletingUser, password)) {
                    throw new RuntimeException(
                            "Delete failed, You do not have the permissions needed to delete all the objects specified.");
                }
            } else {
                HierarchyNode thisNode = hierarchyNodeDAO.getById(thisNodeId);
                if (thisNode == null) {
                    continue;
                }
                if (isDeletionBlocked(deletingUser, thisNode)) {
                    throw new RuntimeException(
                            "Delete failed, You do not have the permissions needed to delete all the objects specified.");
                }
            }
        }
    }

    private boolean isDeletionBlocked(final User user, final HierarchyNode node) {
        for(Password password : node.getPasswords().values()) {
            if (isDeletionBlocked(user, password)) {
                return true;
            }
        }

        for(HierarchyNode thisNode : node.getChildren().values()) {
            if(isDeletionBlocked(user, thisNode)) {
                return true;
            }
        }

        return false;
    }

    private boolean isDeletionBlocked(final User user, final Password password) {
        PasswordAccessControl accessControl =
                daoRepository.getPasswordAccessControlDAO().getAccessControl(user, password);
        return accessControl == null;
    }

    private void deleteSpecifiedNodes(User deletingUser, HierarchyNode parent, String[] nodes) {
        HierarchyNodeDAO hierarchyNodeDAO = daoRepository.getHierarchyNodeDAO();
        for (String thisNodeId : nodes) {
            if (thisNodeId == null) {
                continue;
            }

            try {
                if (thisNodeId.startsWith("p_")) {
                    deletePassword(deletingUser, parent, thisNodeId.substring(2));
                } else {
                    deleteNode(deletingUser, hierarchyNodeDAO, thisNodeId);
                }
            } catch (GeneralSecurityException e) {
                Logger.getAnonymousLogger().log(Level.SEVERE, "Unable to log deletion.", e);
            }
        }

    }

    private void deleteNode(User deletingUser, HierarchyNodeDAO hierarchyNodeDAO, String nodeId)
            throws GeneralSecurityException {
        HierarchyNode node = hierarchyNodeDAO.getById(Long.parseLong(nodeId));
        if (node == null) {
            return;
        }

        logStore.log(LogEventClass.HIERARCHY_MANIPULATION, deletingUser,
                "Deleted the node "+hierarchyNodeDAO.getPathAsString(node));
        hierarchyNodeDAO.delete(node);
    }

    private void deletePassword(User deletingUser, HierarchyNode parent, String passwordId) throws GeneralSecurityException {
        logStore.log(LogEventClass.HIERARCHY_MANIPULATION, deletingUser,
                "Deleted the password {password:"+passwordId+"}");
        Password password = parent.getPasswords().get(Long.parseLong(passwordId));
        password.setEnabled(false);

    }
}
