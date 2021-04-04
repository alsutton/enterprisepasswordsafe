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
import com.enterprisepasswordsafe.model.persisted.IntegrationModuleConfiguration;
import com.enterprisepasswordsafe.model.persisted.IntegrationModuleScript;
import com.enterprisepasswordsafe.model.persisted.Password;

import javax.persistence.EntityManager;
import javax.persistence.TypedQuery;
import java.util.HashMap;
import java.util.Map;

public final class IntegrationModuleConfigurationDAO
		extends JPADAOBase<IntegrationModuleConfiguration> {

	public static final String MODULE_CONFIGURED_PARAMETER = "_ACTIVE";

	public IntegrationModuleConfigurationDAO(DAORepository daoRepository, EntityManager entityManager) {
		super(daoRepository, entityManager, IntegrationModuleConfiguration.class);
	}

    public boolean scriptIsInUse( final IntegrationModuleScript script ) {
		return !script.getConfigurationOptions().isEmpty();
    }

    public Map<String,String> getProperties(final IntegrationModuleScript script, final Password password) {
		Map<String,String> properties = new HashMap<>();
		// Populate with defaults
		populateMapWithProperties(properties, script, null);
		// Add with password specific values
		populateMapWithProperties(properties, script, password);
		return properties;
	}

	private void populateMapWithProperties(Map<String,String> properties,
										   final IntegrationModuleScript script,
										   Password password) {
		TypedQuery<IntegrationModuleConfiguration> query = entityManager.createQuery(
				"SELECT configuration "+
						" FROM IntegrationModuleConfiguration configuration "+
						"WHERE  configuration.script = :script AND configuration.password = :password",
				IntegrationModuleConfiguration.class);
		query.setParameter("script", script);
		query.setParameter("password", password);
		query.getResultStream()
			.forEach(configuration -> properties.put(configuration.getName(), configuration.getValue()));
    }
}
