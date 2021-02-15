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

import com.alsutton.cryptography.Encrypter;
import com.alsutton.cryptography.SymmetricDecrypter;
import com.alsutton.cryptography.SymmetricEncrypter;
import com.enterprisepasswordsafe.model.DAORepository;
import com.enterprisepasswordsafe.model.ReservedGroups;
import com.enterprisepasswordsafe.model.cryptography.EncrypterFactory;
import com.enterprisepasswordsafe.model.cryptography.IVUtils;
import com.enterprisepasswordsafe.model.persisted.Group;
import com.enterprisepasswordsafe.model.persisted.Membership;
import com.enterprisepasswordsafe.model.persisted.User;

import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.TypedQuery;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;

public final class MembershipDAO
		extends JPADAOBase<Membership> {

    public MembershipDAO(DAORepository daoRepository, EntityManager entityManager) {
		super(daoRepository, entityManager, Membership.class);
	}

	/**
	 * Is the user one of the groups with higher access privilieges
	 *
	 * @param user The user to test
	 * @return true if they are priviledged, false if not
	 */

	public boolean isPriviledgedUser(User user) {
		return isAdminUser(user) || isSubadminUser(user);
	}

	/**
	 * Is the user one of the groups with the highest access.
	 *
	 * @param user The user to test.
	 * @return true if they are a full admin, false if not.
	 */

	public boolean isAdminUser(User user) {
		return isMemberOf(user, ReservedGroups.ADMIN.getId());
	}

	/**
	 * Is the user in the subadministrator group.
	 *
	 * @param user The user to test.
	 * @return true if the user is a subadmin, false if not.
	 */

	public boolean isSubadminUser(User user) {
		return isMemberOf(user, ReservedGroups.SUBADMIN.getId());
	}

	/**
     * Writes a group membership to the database.
     *
     * @param user The user involved in the membership.
     * @param membership The membership to store.
     *
     * @throws GeneralSecurityException Thrown if there was a decryption problem.
     */

    public void write(final User user, Membership membership)
        throws GeneralSecurityException {
		SymmetricEncrypter encrypter =
				new SymmetricEncrypter(user.getKey(), IVUtils.generateFrom(membership.getUuid()));
		membership.encryptGroupKey(encrypter);
		store(membership);
    }

    /**
     * Creates a new membership for a user to a group
     *
     * @param user The user who is joining the group.
     * @param group The group they are joining.
     *
     * @throws GeneralSecurityException Thrown if there was a decryption problem.
     */

    public void create(final User user, final Group group)
    	throws GeneralSecurityException {
        Membership membership = getMembership(user, group);
        if( membership == null) {
            membership = new Membership(user, group);
            write(user, membership);
        }
	}

   /**
     * Creates a new membership for a user to a group
     *
     * @param remoteUser The user adding the specified user to the group.
     * @param user The user who is joining the group.
     * @param group The group they are joining.
     *
     * @throws GeneralSecurityException Thrown if there was a decryption problem.
     */

    public void create(final User remoteUser, final User user, final Group group)
            throws GeneralSecurityException {
        Membership membership = getMembership(remoteUser, group);
        if(membership == null) {
            // Go via the admin user if there is no direct membership.
            User adminUser = daoRepository.getUserDAO().getAdminUserForUser(remoteUser);
            membership = getMembership(adminUser, group);
        }
        group.setKey(membership.getKey());

        create(user, group);
	}

	/**
	 * Get a users membership of a group.
	 *
	 * @param user The user to get the membership for.
	 * @param group The group to get the membership of.
	 *
	 * @return A membership object or null if it does not exist.
	 */

	public Membership getMembership(final User user, final Group group)
			throws GeneralSecurityException {
    	Membership membership = getEncryptedMembership(user, group);
    	if(membership == null) {
    		return null;
		}

    	SymmetricDecrypter decrypter = getDecrypterForMembership(user, membership);
    	membership.decryptGroupKey(decrypter);
    	return membership;
	}

	private Membership getEncryptedMembership(final User user, final Group group) {
	    if (user == null || group == null) {
	        return null;
	    }

	    try {
			TypedQuery<Membership> query =
					entityManager.createNamedQuery("Membership.getSpecificMembership", Membership.class);
			query.setParameter("user", user);
			query.setParameter("group", group);
			return query.getSingleResult();
		} catch (NoResultException e) {
	    	return null;
		}
	}

	/**
	 * Get a users membership of a group.
	 *
	 * @param user The user to get the membership for.
	 * @param group The group to get the membership of.
	 *
	 * @return A membership object or null if it does not exist.
	 */

	public boolean isMemberOf(final User user, final Group group) {
	    if (user == null || group == null) {
	        return false;
	    }

	    return isMemberOf(user, group.getId());
	}

	public boolean isMemberOf(final User user, final ReservedGroups group) {
		if (user == null || group == null) {
			return false;
		}

		return isMemberOf(user, group.getId());
	}

	private boolean isMemberOf(final User user, final Long groupId) {
		try {
			TypedQuery<Membership> query =
					entityManager.createNamedQuery("Membership.getSpecificMembershipById", Membership.class);
			query.setParameter("user", user);
			query.setParameter("groupId", groupId);
			return query.getSingleResult() != null;
		} catch (NoResultException e) {
			return false;
		}
	}

	/**
	 * Remove a user from a group
	 *
     * @param user The user to delete the membership for.
	 * @param group The group to delete the membership for.
	 */

	public void delete(final User user, final Group group) {
        Membership membership = getEncryptedMembership(user, group);
        if (membership != null) {
        	delete(membership);
		}
	}

    /**
     * Update the encryption on the memberships of a user.
     *
     * @param user The user to update the memberships for.
     * @param encrypterFactory The factory for Encrypters to use to update the memberships.
     *
     * @throws GeneralSecurityException Thrown if there is a problem re-encrypting the keys.
     */

    public void updateEncryptionOnKeys(final User user, final EncrypterFactory encrypterFactory)
        throws GeneralSecurityException {
        if (user == null) {
            return;
        }

		// Two phase to ensure we don't modify the objects at the same time as we're trying to read them
		Collection<Membership> memberships = user.getMemberships().values();
        for(Membership membership : memberships) {
        	SymmetricDecrypter symmetricDecrypter = getDecrypterForMembership(user, membership);
        	membership.decryptGroupKey(symmetricDecrypter);
		}
		for(Membership membership : memberships) {
			Encrypter encrypter = encrypterFactory.encrypterFor(membership);
			membership.encryptGroupKey(encrypter);
		}
    }

    private SymmetricDecrypter getDecrypterForMembership(User user, Membership membership)
			throws NoSuchAlgorithmException {
    	return new SymmetricDecrypter(user.getKey(), IVUtils.generateFrom(membership.getUuid()));
	}
}
