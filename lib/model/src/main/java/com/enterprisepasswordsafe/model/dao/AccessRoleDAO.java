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

import com.enterprisepasswordsafe.model.AccessRoles;
import com.enterprisepasswordsafe.model.DAORepository;
import com.enterprisepasswordsafe.model.EntityState;
import com.enterprisepasswordsafe.model.persisted.GroupAccessRole;
import com.enterprisepasswordsafe.model.persisted.Membership;
import com.enterprisepasswordsafe.model.persisted.Password;
import com.enterprisepasswordsafe.model.persisted.User;
import com.enterprisepasswordsafe.model.persisted.UserAccessRole;

import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.TypedQuery;
import java.util.HashSet;
import java.util.Set;

/**
 * Data access object for the user objects.
 */
public final class AccessRoleDAO extends JPADAOBase<GroupAccessRole> {

	public AccessRoleDAO(DAORepository daoRepository, EntityManager entityManager) {
		super(daoRepository, entityManager, GroupAccessRole.class);
	}

	public Set<User> getApprovers(User requestingUser, Password item ) {
		HashSet<User> approvers = new HashSet<>();

		addUsersFromGroupRoles(item, approvers);
		addUsersFromUserRoles(item, approvers);

		if(requestingUser != null) {
	        approvers.remove(requestingUser);
		}

		return approvers;
	}

	private void addUsersFromGroupRoles(Password item, Set<User> approvers) {
		TypedQuery<GroupAccessRole> query =
				entityManager.createNamedQuery(
						"GroupAccessRole.getApproversForPassword",
						GroupAccessRole.class);
		query.setParameter("password", item);
		query.setParameter("state", EntityState.ENABLED);
		query.setParameter("role", AccessRoles.APPROVER);
		for(GroupAccessRole role : query.getResultList()) {
			for(Membership membership : role.getGroup().getMemberships().values()) {
				approvers.add(membership.getUser());
			}
		}
	}

	private void addUsersFromUserRoles(Password item, Set<User> approvers) {
		TypedQuery<UserAccessRole> query =
				entityManager.createNamedQuery(
						"UserAccessRole.getApproversForPassword",
						UserAccessRole.class);
		query.setParameter("password", item);
		query.setParameter("state", EntityState.ENABLED);
		query.setParameter("role", AccessRoles.APPROVER);
		for(UserAccessRole role : query.getResultList()) {
			approvers.add(role.getUser());
		}
	}

	public boolean hasRole(final User user, final Password item, final AccessRoles role) {
		return hasDirectRole(user, item, role) | hasIndirectRole(user, item, role);
	}

	private boolean hasDirectRole(final User user, final Password item, final AccessRoles role) {
		TypedQuery<UserAccessRole> query =
				entityManager.createNamedQuery(
						"UserAccessRole.getRoleForPasswordAndUser",
						UserAccessRole.class);
		query.setParameter("user", user);
		query.setParameter("password", item);
		try {
			return query.getSingleResult().getRole().equals(role);
		} catch (NoResultException e) {
			return false;
		}
	}

	private boolean hasIndirectRole(final User user, final Password item, final AccessRoles role) {
		TypedQuery<GroupAccessRole> query =
				entityManager.createNamedQuery(
						"GroupAccessRole.getRolesForPasswordAndUser",
						GroupAccessRole.class);
		query.setParameter("user", user);
		query.setParameter("password", item);
		query.setParameter("groupState", EntityState.ENABLED);
		for(GroupAccessRole groupRole : query.getResultList()) {
			if(groupRole.getRole().equals(role)) {
				return true;
			}
		}
		return false;
	}
}
