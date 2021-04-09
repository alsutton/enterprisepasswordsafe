package com.enterprisepasswordsafe.engine.hierarchy;

import com.enterprisepasswordsafe.model.DAORepository;
import com.enterprisepasswordsafe.model.dao.HierarchyNodeDAO;
import com.enterprisepasswordsafe.model.persisted.HierarchyNode;
import com.enterprisepasswordsafe.model.persisted.Password;
import com.enterprisepasswordsafe.model.persisted.User;
import com.enterprisepasswordsafe.passwordprocessor.actions.NodeObjectAction;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Set;

public class HierarchyTools {

    private final DAORepository daoRepository;

    public HierarchyTools(DAORepository daoRepository) {
        this.daoRepository = daoRepository;
    }

    public List<HierarchyNode> getParentage(final HierarchyNode node)
            throws SQLException {
        final List<HierarchyNode> parentage = new ArrayList<>();
        HierarchyNode currentNode = node;
        while (currentNode != null ) {
            parentage.add(0, currentNode);
            currentNode = currentNode.getParent();
        }

        return parentage;
    }

    public String getParentageAsText(final HierarchyNode node)
            throws SQLException {
        return daoRepository.getHierarchyNodeDAO().getPathAsString(node);
    }

    public HierarchyNodeChildren getChildrenValidForUser(final HierarchyNode node, final User theUser, boolean includeEmpty,
                                                         final Comparator<HierarchyNode> nodeComparator, final Comparator<Password> objectComparator)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        HierarchyNodeDAO hierarchyNodeDAO = daoRepository.getHierarchyNodeDAO();

        Collection<HierarchyNode> containers =
                hierarchyNodeDAO.getChildrenContainerNodesForUser(node, theUser, includeEmpty, nodeComparator);
        Set<Password> objects =
                hierarchyNodeDAO.getAllChildrenObjects(node, theUser, objectComparator);

        return ImmutableHierarchyNodeChildren.builder().nodes(containers).objects(objects).build();
    }

    public void processObjectNodes(final HierarchyNode node, final User theUser,
                                   final NodeObjectAction action, final boolean recurse)
            throws Exception {
        HierarchyNodeDAO hierarchyNodeDAO = daoRepository.getHierarchyNodeDAO();
        if(recurse) {
            for( HierarchyNode thisNode : hierarchyNodeDAO.getChildrenContainerNodesForUser(node, theUser, true, null)) {
                processObjectNodes(thisNode, theUser, action, true);
            }
        }

        for(Password password: hierarchyNodeDAO.getAllChildrenObjects(node, theUser, null)) {
            action.process(node, password);
        }
    }
}
