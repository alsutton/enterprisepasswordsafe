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
import com.enterprisepasswordsafe.model.persisted.LogEntry;

import javax.persistence.EntityManager;
import javax.persistence.TypedQuery;
import java.util.Date;
import java.util.List;

public class LoggingDAO extends JPADAOBase<LogEntry> {

	public LoggingDAO(DAORepository daoRepository, EntityManager entityManager) {
		super(daoRepository, entityManager, LogEntry.class);
	}

    public List<LogEntry> getEventsForDateRange(final Date startDate, final Date endDate) {
        TypedQuery<LogEntry> logEntries =
                entityManager.createNamedQuery("LogEntry.forDateRage", LogEntry.class);
        logEntries.setParameter("start", startDate);
        logEntries.setParameter("end", endDate);
        return logEntries.getResultList();
    }
}
