/*
 * Copyright (c) 2017 Carbon Security Ltd. <opensource@carbonsecurity.co.uk>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package com.enterprisepasswordsafe.model.dao;

import com.alsutton.cryptography.Decrypter;
import com.alsutton.cryptography.TwoLevelDecrypter;
import com.enterprisepasswordsafe.accesscontrol.AbstractAccessControl;
import com.enterprisepasswordsafe.model.DAORepository;
import com.enterprisepasswordsafe.model.Permission;
import com.enterprisepasswordsafe.model.persisted.HierarchyNode;
import com.enterprisepasswordsafe.model.persisted.Password;
import com.enterprisepasswordsafe.model.persisted.User;

import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.Query;
import javax.persistence.TypedQuery;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.Stack;
import java.util.TreeSet;
import java.util.stream.Stream;

/**
 * Data access object for nodes in the hierarchy.
 */
public final class HierarchyNodeDAO
    extends JPADAOBase<HierarchyNode> {

    public HierarchyNodeDAO(DAORepository daoRepository, EntityManager entityManager) {
        super(daoRepository, entityManager, HierarchyNode.class);
    }

    /**
	 * Create a new hierarchy node
	 */

    public HierarchyNode create (final HierarchyNode parent, final String name)
    	throws SQLException, GeneralSecurityException {
    	if( parent.getChildren().containsKey(name) ) {
    		throw new GeneralSecurityException ("A node with that name already exists");
    	}
    	HierarchyNode node = new HierarchyNode(parent,name);
    	store(node);
    	return node;
    }


    public Set<Password> getAllChildrenObjects(final HierarchyNode node, final User user,
                                               final Comparator<Password> comparator)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        Set<Password> results = comparator == null ? new HashSet<>() : new TreeSet<>(comparator);
        addUserAccessControlAccessibleObjects(node, user, results);
        addGroupAccessControlAccessibleObjects(node, user, results);
        return results;
    }

    private void addUserAccessControlAccessibleObjects(final HierarchyNode node, final User user,
                                                        Set<Password> results) {
        addAccessibleObjects(node, user, results, "HierarchyNode.getPasswordsAccessibleViaUACForUser",
                daoRepository.getPasswordAccessControlDAO());
    }

    private void addGroupAccessControlAccessibleObjects(final HierarchyNode node, final User user,
                                                        Set<Password> results) {
        addAccessibleObjects(node, user, results, "HierarchyNode.getPasswordsAccessibleViaGACForUser",
                daoRepository.getPasswordAccessControlDAO());
    }

    private void addAccessibleObjects(final HierarchyNode node, final User user,
                                      Set<Password> results, String queryName,
                                      PasswordAccessControlDAO acDAO) {
        boolean userIsPriviledged =
                daoRepository.getMembershipDAO().isPriviledgedUser(user);

        getAccessiblePasswords(node, user, queryName)
                .filter(password -> userIsPriviledged || password.getEnabled())
                .forEach(password -> {
                    AbstractAccessControl ac = acDAO.getReadAccessControl(user, password);
                    try {
                        processResult(results, ac, password);
                    } catch (GeneralSecurityException | IOException e) {
                        e.printStackTrace();
                    }
                });
    }

    private Stream<Password> getAccessiblePasswords(final HierarchyNode node, final User user,
                                                    final String queryName) {
        TypedQuery<Password> accessiblePasswords =
                entityManager.createNamedQuery(queryName, Password.class);
        accessiblePasswords.setParameter("user", user);
        accessiblePasswords.setParameter("node", node);
        return accessiblePasswords.getResultStream();
    }

    private void processResult(Set<Password> results, AbstractAccessControl accessControl, Password password)
            throws GeneralSecurityException, IOException {
        if(accessControl == null) {
            return;
        }
        Decrypter decrypter = new TwoLevelDecrypter(accessControl.getReadKey());
        byte[] data = password.decrypt(password::getData, decrypter);
        Properties properties = new Properties();
        properties.load(new ByteArrayInputStream(data));
        password.setDecryptedProperties(properties);
        results.add(password);
    }

    public Collection<HierarchyNode> getChildrenContainerNodesForUser(final HierarchyNode node,
            final User theUser, boolean includeEmpty, final Comparator<HierarchyNode> comparator)
        throws SQLException, GeneralSecurityException {
        Collection<HierarchyNode> children = node.getChildren().values();
        if( daoRepository.getMembershipDAO().isAdminUser(theUser)) {
            return children;
        }

        children.removeAll(getNodesBlockedForUser(theUser, includeEmpty, children));

        if (comparator != null) {
            List<HierarchyNode> sortedChildren = new ArrayList<>(children);
            sortedChildren.sort(comparator);
            children = sortedChildren;
        }

        return children;
    }

    private List<HierarchyNode> getNodesBlockedForUser(User theUser, boolean includeEmpty,
                                                       Collection<HierarchyNode> children)
            throws GeneralSecurityException {
        HierarchyNodeAccessRuleDAO hnarDAO = daoRepository.getHierarchyNodeAccessRuleDAO();
        List<HierarchyNode> blockedNodes= new ArrayList<>();
        for(HierarchyNode thisNode : children) {
            if (hnarDAO.getAccessibilityForUser(thisNode, theUser, false) == Permission.DENY
            ||  (!includeEmpty && !hasChildrenValidForUser(thisNode, theUser) )) {
                blockedNodes.add(thisNode);
            }
        }
        return blockedNodes;
    }

    /**
     * Tests to see if there are subnodes which the user can access which hold entries.
     *
     * @param node The node to test.
     * @param user The user form whom the check should be performed.
     *
     * @return true if there are nodes with data in, false if not.
     *
     * @throws GeneralSecurityException Thrown if there is a problem decrypting the data.
     */

    private boolean hasChildrenNodes(final HierarchyNode node, final User user)
            throws GeneralSecurityException {
        Collection<HierarchyNode> childNodes = node.getChildren().values();
        if(childNodes.isEmpty()) {
            return false;
        }

        if (daoRepository.getMembershipDAO().isPriviledgedUser(user)) {
            return true;
        }

        for(HierarchyNode childNode : childNodes) {
            if (hasChildrenValidForUser(childNode, user)) {
                return true;
            }
        }

        return false;
    }

    public HierarchyNode getPersonalNodeForUser(final User user) {
        TypedQuery<HierarchyNode> query =
                entityManager.createQuery(
                        "SELECT h FROM HierarchyNode h WHERE h.owner = :user AND h.parent is null",
                        HierarchyNode.class);
        query.setParameter("user", user);
        try {
            return query.getSingleResult();
        } catch (NoResultException e) {
            return null;
        }
    }

    /**
     * Tests if a node has children which a user can access.
     *
     * @param node The ID of the HierarchyNode to check.
     * @param user The user to check access for.
     *
     * @return true if this node contains user accessible data, false if not.
     *
     * @throws GeneralSecurityException Thrown if there is a problem decrypting the data.
     */

    private boolean hasChildrenValidForUser(final HierarchyNode node, final User user)
            throws GeneralSecurityException {
        return hasResults(node, user, "HierarchyNode.getPasswordsAccessibleViaUACForUser")
            || hasResults(node, user, "HierarchyNode.getPasswordsAccessibleViaGACForUser")
            || hasChildrenNodes(node, user);
    }

    private boolean hasResults(final HierarchyNode node, final User user, final String testQuery) {
        Query q = entityManager.createNamedQuery(testQuery);
        q.setParameter("node", node);
        q.setParameter("user", user);
        q.setMaxResults(1);
        return !q.getResultList().isEmpty();
    }

    public String getPathAsString(HierarchyNode node) {
        Stack<String> parentage = new Stack<>();
        int pathSize = buildNodePath(node, parentage);

        StringBuilder path = new StringBuilder(pathSize);
        parentage.forEach(element -> {
                    path.append(element);
                    path.append('\\');
                });
        return parentage.toString();
    }

    private int buildNodePath(HierarchyNode node, Stack<String> path) {
        if (node == null) {
            return 0;
        }
        String name = node.getName();
        path.push(name);
        return name.length() + 1 + buildNodePath(node.getParent(), path);
    }

}
