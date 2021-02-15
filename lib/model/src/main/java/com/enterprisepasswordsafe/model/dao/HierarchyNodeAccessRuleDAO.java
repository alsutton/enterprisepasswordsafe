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

import com.enterprisepasswordsafe.model.ConfigurationOptions;
import com.enterprisepasswordsafe.model.DAORepository;
import com.enterprisepasswordsafe.model.Permission;
import com.enterprisepasswordsafe.model.ReservedGroups;
import com.enterprisepasswordsafe.model.ReservedHierarchyNodes;
import com.enterprisepasswordsafe.model.ReservedUsers;
import com.enterprisepasswordsafe.model.persisted.AbstractActor;
import com.enterprisepasswordsafe.model.persisted.Group;
import com.enterprisepasswordsafe.model.persisted.HierarchyNode;
import com.enterprisepasswordsafe.model.persisted.HierarchyNodeAccessRule;
import com.enterprisepasswordsafe.model.persisted.User;

import javax.persistence.EntityManager;
import javax.persistence.TypedQuery;
import java.util.List;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Data access object for hierarchy node access rules.
 */

public class HierarchyNodeAccessRuleDAO
	extends JPADAOBase<HierarchyNodeAccessRule> {

	public HierarchyNodeAccessRuleDAO(DAORepository daoRepository, EntityManager entityManager) {
		super(daoRepository, entityManager, HierarchyNodeAccessRule.class);
	}

	public Permission getAccessibilityForUser(final HierarchyNode node, final User user) {
    	return getAccessibilityForUser( node, user, true);
    }

    public Permission getAccessibilityForUser( final HierarchyNode node, final User user, boolean recurse) {
		ConfigurationDAO configurationDAO = daoRepository.getConfigurationDAO();

		if(node == null || ReservedHierarchyNodes.SYSTEM_ROOT.matches(node)) {
			String defaultRule =
				configurationDAO.get(ConfigurationOptions.DEFAULT_HIERARCHY_ACCESS_RULE);
			return defaultRule != null && defaultRule.equals("D") ? Permission.DENY : Permission.ALLOW;
		}

		String permissionPrecedence =
				daoRepository.getConfigurationDAO().get(ConfigurationOptions.PERMISSION_PRECEDENCE);

		Permission permission;
		HierarchyNode currentNode = node;
		do {
			permission = permissionPrecedence.equals("G") ?
					fetchInOrder(currentNode, user, this::getAccessibilityRule, this::getAccessibilityRuleViaGroups) :
					fetchInOrder(currentNode, user, this::getAccessibilityRuleViaGroups, this::getAccessibilityRule);
			currentNode = currentNode.getParent();
		} while(recurse && !permission.isEnforceable());

		return permission;
	}

	private Permission fetchInOrder(HierarchyNode node, User user,
									BiFunction<HierarchyNode, User, Permission> first,
									BiFunction<HierarchyNode, User, Permission> second) {
		Permission permission = first.apply(node, user);
		if(permission != null && permission.isEnforceable()) {
			return permission;
		}
		return second.apply(node, user);
	}

    protected Permission getAccessibilityRule(final HierarchyNode node, final AbstractActor actor) {
		HierarchyNodeAccessRule accessRule = node.getAccessRules().get(actor);
		return accessRule == null ? Permission.APPLY_DEFAULT : accessRule.getPermission();
    }

    protected List<Permission> getUsersGroupAccessibilityRules( final HierarchyNode node, final User user) {
		TypedQuery<HierarchyNodeAccessRule> query =
				entityManager.createQuery(
						"SELECT hnar FROM HierarchyNodeAccessRule hnar, Membership m "+
								"WHERE hnar.node = : node AND m.user = :user AND hnar.actor = m.group",
						HierarchyNodeAccessRule.class);
		query.setParameter("node", node);
		query.setParameter("user", user);
		return query.getResultStream()
				.flatMap(hnar -> Stream.of(hnar.getPermission()))
				.collect(Collectors.toList());
    }

    public Set<HierarchyNodeAccessRule> getUserAccessibilityRules(final HierarchyNode node) {
    	return node.getAccessRules().values().stream()
				.filter(hnar -> (hnar.getActor() instanceof User))
				.filter(hnar -> !ReservedUsers.ADMIN.matches((User)hnar.getActor()))
				.collect(Collectors.toSet());
    }

    public Set<HierarchyNodeAccessRule> getGroupAccessibilityRules( final HierarchyNode node ) {
		return node.getAccessRules().values().stream()
				.filter(hnar -> (hnar.getActor() instanceof Group))
				.filter(hnar -> !ReservedGroups.isSystemGroup((Group)hnar.getActor()))
				.collect(Collectors.toSet());
    }

    public void setAccessiblity( final HierarchyNode node, final AbstractActor actor, final Permission permission) {
    	if (permission == Permission.APPLY_DEFAULT) {
			node.getAccessRules().remove(actor);
    		return;
    	}

    	HierarchyNodeAccessRule hnar = node.getAccessRules().get(actor);
		if (hnar == null) {
			hnar = new HierarchyNodeAccessRule(actor, permission, node);
		} else {
			hnar.setPermission(permission);
		}

		store(hnar);
    }

	/**
	 * Check to see if the user has an explicit permission via their group membership.
	 *
	 * @param node The node to check the rules for.
	 * @param user The user to check the rules for.
	 * @return Boolean.FALSE if there was a deny rule, Boolean.TRUE if all the rules
	 * 		were allow rules, and null if no explicit rules were found.
	 */
	Permission getAccessibilityRuleViaGroups(HierarchyNode node, User user) {
		boolean explicitlyAllowed = false;
		List<Permission> permissions = getUsersGroupAccessibilityRules(node, user);
		for (Permission permission : permissions) {
			if (permission == Permission.DENY) {
				return permission;
			} else if (permission == Permission.ALLOW) {
				explicitlyAllowed = true;
			}
		}
    	return explicitlyAllowed ? Permission.ALLOW : Permission.APPLY_DEFAULT;
	}
}
