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

import com.enterprisepasswordsafe.model.DAORepository;
import com.enterprisepasswordsafe.model.Permission;
import com.enterprisepasswordsafe.model.persisted.IPZone;
import com.enterprisepasswordsafe.model.persisted.User;
import com.enterprisepasswordsafe.model.persisted.UserIPZoneRestriction;
import com.enterprisepasswordsafe.model.utils.IPZoneUtils;

import javax.persistence.EntityManager;
import javax.persistence.TypedQuery;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.util.List;

public final class UserIPZoneRestrictionDAO extends JPADAOBase<UserIPZoneRestriction> {

	private UserIPZoneRestrictionDAO(DAORepository daoRepository, EntityManager entityManager) {
		super(daoRepository, entityManager, UserIPZoneRestriction.class);
	}

    public final void create(final User user, final IPZone zone, final Permission rule ) {
    	UserIPZoneRestriction ipzr = new UserIPZoneRestriction(user, zone, rule);
    	store(ipzr);
    }

    public void store( final UserIPZoneRestriction ipzr ) {
        entityManager.persist(ipzr);
    }

    public void delete( final UserIPZoneRestriction ipzr ) {
        entityManager.detach(ipzr);
    }

    public final List<UserIPZoneRestriction> getApplicable( final User user, final String ip )
        throws UnknownHostException, GeneralSecurityException {

        int ipVersion;
        String dbString;
        if (ip.indexOf('.') == -1 && ip.indexOf(':') != -1) {
            ipVersion = 6;
            dbString = IPZoneUtils.convertIP6ToDBString(ip);
        } else {
            ipVersion = 4;
            dbString = IPZoneUtils.convertIP4ToDBString(ip);
        }

        TypedQuery<UserIPZoneRestriction> query =
                entityManager.createNamedQuery(
                        "UserIPZoneRestriction.userAndIPAddress",
                        UserIPZoneRestriction.class);
        query.setParameter("user", user);
        query.setParameter("ipVersion", ipVersion);
        query.setParameter("ipAddress", dbString);
        return query.getResultList();
    }

    public final UserIPZoneRestriction getByZoneAndUser( final User user, final IPZone zone ) {
        TypedQuery<UserIPZoneRestriction> query =
                entityManager.createNamedQuery(
                        "UserIPZoneRestriction.userAndZone",
                        UserIPZoneRestriction.class);
        query.setParameter("user", user);
        query.setParameter("zone", zone);
        return query.getSingleResult();
    }
}
