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

import com.alsutton.cryptography.SymmetricKeySupplier;
import com.enterprisepasswordsafe.model.DAORepository;
import com.enterprisepasswordsafe.model.EntityState;
import com.enterprisepasswordsafe.model.ReservedGroups;
import com.enterprisepasswordsafe.model.ReservedUsers;
import com.enterprisepasswordsafe.model.persisted.Group;
import com.enterprisepasswordsafe.model.persisted.Membership;
import com.enterprisepasswordsafe.model.persisted.User;

import javax.persistence.EntityManager;
import javax.persistence.TypedQuery;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Data access object for the group objects.
 */
public class GroupDAO extends JPADAOBase<Group> {

	private final SymmetricKeySupplier symmetricKeySupplier = new SymmetricKeySupplier();

	public GroupDAO(DAORepository daoRepository, EntityManager entityManager) {
		super(daoRepository, entityManager, Group.class);
	}

    public Group create(final User theCreator, final String groupName)
    	throws GeneralSecurityException, UnsupportedEncodingException {
        Group theGroup = getByName(groupName);
        if (theGroup != null) {
            throw new GeneralSecurityException("The group already exists");
        }

        // Create the group and ensure that user 0 is a member.
        Group newGroup = new Group(groupName);
        newGroup.setKey(symmetricKeySupplier.generateKey());
        write(newGroup);

        MembershipDAO membershipDAO = daoRepository.getMembershipDAO();
        membershipDAO.create(theCreator, newGroup);

        // Ensure the creating user is part of the group if they are not the
        // admin user.
        if (!ReservedUsers.ADMIN.matches(theCreator)) {
        	membershipDAO.create(theCreator, newGroup);
        }

        return newGroup;
    }

    public Group getAdminGroup(final User theUser)
            throws GeneralSecurityException {
        Group adminGroup = getByIdWithKeyAvailable(ReservedGroups.ADMIN.getId(), theUser);
        if (adminGroup != null) {
            return adminGroup;
        }

        return getByIdWithKeyAvailable(ReservedGroups.SUBADMIN.getId(), theUser);
    }

    public Group getByIdWithKeyAvailable(final ReservedGroups reservedGroup, final User user)
            throws GeneralSecurityException {
	    return getByIdWithKeyAvailable(reservedGroup.getId(), user);
    }

    public Group getByIdWithKeyAvailable(final Long id, final User user)
            throws GeneralSecurityException {
    	Group group = entityManager.find(Group.class, id);
    	if( group == null || group.getState() == EntityState.DELETED) {
    		return null;
    	}

    	Membership mem = daoRepository.getMembershipDAO().getMembership(user, group);
    	if( mem == null ) {
    		return null;
    	}

        group.setKey(mem.getKey());
    	return group;
    }

    public Group getByName(String name) {
	    return getWithSingleParameter("Group.getByName", "name", name);
    }

    public Group getById(ReservedGroups group) {
	    return getById(group.getId());
    }

    public void write(final Group group) {
	    entityManager.persist(group);
    }

    public List<Group> getAll() {
        TypedQuery<Group> query = entityManager.createQuery("SELECT g FROM Group g", Group.class);
    	return query.getResultList();
    }

    public List<Group> getNonSystem() {
	    return getAll().stream()
                .filter(g -> !ReservedGroups.isSystemGroup(g))
                .collect(Collectors.toList());
    }

    public List<Group> getAllEnabled() {
        return getAll().stream()
                .filter(g -> g.getState() == EntityState.ENABLED)
                .collect(Collectors.toList());
    }

    public List<Group> searchNames(String searchQuery) {
        if(searchQuery == null) {
            searchQuery = "%";
        } else if(searchQuery.indexOf('%') == -1) {
            searchQuery += "%";
        }

        TypedQuery<Group> query =
                entityManager.createQuery(
                        "SELECT g FROM Group g WHERE g.name like :searchQuery",
                        Group.class);
        query.setParameter("searchQuery", searchQuery);
        return query.getResultList();
    }

    public boolean nameExists(String groupName) {
    	return (getByName(groupName) != null);
    }

    public boolean idExists(Long id) {
    	return entityManager.find(Group.class, id) != null;
    }
}
