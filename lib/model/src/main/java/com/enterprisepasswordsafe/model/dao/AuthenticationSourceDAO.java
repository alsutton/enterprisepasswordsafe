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
import com.enterprisepasswordsafe.model.persisted.AuthenticationProperty;
import com.enterprisepasswordsafe.model.persisted.AuthenticationSource;

import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.TypedQuery;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;

public class AuthenticationSourceDAO extends JPADAOBase<AuthenticationSource> {

	public AuthenticationSourceDAO(DAORepository daoRepository, EntityManager entityManager) {
		super(daoRepository, entityManager, AuthenticationSource.class);
	}

	public void create(final String name, final String jaasType,
                       final Map<String,String> properties)
		throws SQLException, GeneralSecurityException {
		if( existsByName(name) )  {
			throw new GeneralSecurityException("A source with that name already exists");
		}
		AuthenticationSource authenticationSource = new AuthenticationSource(name, jaasType);
		store(authenticationSource);
		for(Map.Entry<String,String> entry : properties.entrySet()) {
            AuthenticationProperty property =
                    new AuthenticationProperty(entry.getKey(), entry.getValue());
            entityManager.persist(property);
        }
    }

    public boolean existsByName(final String sourceName) {
        TypedQuery<AuthenticationSource> query =
                entityManager.createNamedQuery(
                        "AuthenticationSource.getByName",
                        AuthenticationSource.class);
        query.setParameter("name", sourceName);
        try {
            return query.getSingleResult() != null;
        } catch (NoResultException e) {
            return false;
        }
    }

    /**
     * Retrieves all of the AutheticationSource objects as a List.
     *
     * @return The authentication source List.
     */

    public List<AuthenticationSource> getAll() {
        TypedQuery<AuthenticationSource> query =
                entityManager.createNamedQuery("AuthenticationSource.getAll", AuthenticationSource.class);
        return query.getResultList();
    }
}
