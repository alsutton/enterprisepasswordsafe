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

import com.enterprisepasswordsafe.model.ConfigurationListeners;
import com.enterprisepasswordsafe.model.ConfigurationOptions;
import com.enterprisepasswordsafe.model.DAORepository;
import com.enterprisepasswordsafe.model.persisted.ConfigurationOption;

import javax.persistence.EntityManager;
import java.util.List;

public final class ConfigurationDAO extends JPADAOBase<ConfigurationOption> {

	public ConfigurationDAO(DAORepository daoRepository, EntityManager entityManager) {
		super(daoRepository, entityManager, ConfigurationOption.class);
	}

    public String get(ConfigurationOptions option) {
	    if(option == null) {
            return null;
        }

	    String persistedValue = get(option.getPropertyName());
        return persistedValue == null ? option.getDefaultValue() : persistedValue;
    }

    public String get(String name) {
        if(name == null) {
            return null;
        }


        ConfigurationOption persistedValue = getById(name);
        return persistedValue == null ? null : persistedValue.getValue();
    }

    public void set(final String name, final String value) {
        ConfigurationOption option = super.getById(name);
        if(option == null) {
            option = new ConfigurationOption(name);
            option.setName(name);
        }
        option.setValue(value);
        store(option);

        final List<ConfigurationListeners.ConfigurationListener> listeners =
                ConfigurationListeners.getListenersForProperty(option.getName());
        if( listeners != null )
        {
            for(ConfigurationListeners.ConfigurationListener thisListener: listeners) {
                thisListener.configurationChange(option.getName(), value);
            }
        }
    }

    public void delete(final ConfigurationOptions configurationOption) {
	    ConfigurationOption option = getById(configurationOption.getPropertyName());
	    if (option != null) {
            delete(option);
        }
    }

    public void delete(final String name) {
	    delete(getById(name));
    }

    // -- Utility methods to cast the result to an object type

    public Long getLongValue(final ConfigurationOptions configurationOption) {
        try {
            String value = get(configurationOption);
            return parseLongValue(value);
        } catch(NumberFormatException e) {
            try {
                return parseLongValue(configurationOption.getDefaultValue());
            } catch (NumberFormatException nfe) {
                return null;
            }
        }
    }

    private static Long parseLongValue(String value)
            throws NumberFormatException {
        if(value == null) {
            return null;
        }

        return Long.parseLong(value);
    }

    public Boolean getBooleanValue(final ConfigurationOptions configurationOption) {
	    String value = get(configurationOption);
        return value == null ? null : Boolean.parseBoolean(value);
    }
}
