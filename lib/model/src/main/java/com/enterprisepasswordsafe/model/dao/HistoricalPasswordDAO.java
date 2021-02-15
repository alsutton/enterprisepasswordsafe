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

import com.enterprisepasswordsafe.accesscontrol.AccessControl;
import com.enterprisepasswordsafe.model.DAORepository;
import com.enterprisepasswordsafe.model.persisted.HistoricalPassword;
import com.enterprisepasswordsafe.model.persisted.Password;

import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.TypedQuery;
import java.io.IOException;
import java.util.Date;

public class HistoricalPasswordDAO
    extends JPADAOBase<HistoricalPassword> {

    protected HistoricalPasswordDAO(DAORepository daoRepository, EntityManager entityManager) {
        super(daoRepository, entityManager, HistoricalPassword.class);
    }

    public final void store(final Password password)
            throws IOException {
        HistoricalPassword historicalPassword = create(password);
        historicalPassword.setData(password.getData());
        historicalPassword.setExpiry(password.getExpiry());
        store(historicalPassword);
    }

    public final void writeNullEntry(final Password password) {
        HistoricalPassword historicalPassword = create(password);
        store(historicalPassword);
    }

    public HistoricalPassword getForTime(final AccessControl ac, final Password password, final Date dt) {
        if (password == null) {
            return null;
        }

        TypedQuery<HistoricalPassword> query =
                entityManager.createQuery(
                        "SELECT h FROM HistoricalPassword h WHERE h.timestamp < :date ORDER BY h.timestamp DESC",
                        HistoricalPassword.class);
        query.setParameter("date", dt);
        query.setMaxResults(1);
        try {
            return query.getSingleResult();
        } catch (NoResultException e) {
            return null;
        }
    }

    private HistoricalPassword create(Password password) {
        HistoricalPassword historicalPassword = new HistoricalPassword();
        historicalPassword.setTimestamp(new Date());
        historicalPassword.setPassword(password);
        return historicalPassword;
    }
}
