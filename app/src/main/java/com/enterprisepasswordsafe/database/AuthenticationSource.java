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

package com.enterprisepasswordsafe.database;

import com.enterprisepasswordsafe.engine.jaas.*;
import com.enterprisepasswordsafe.engine.utils.IDGenerator;

import java.util.Map;
import java.util.Set;

/**
 * Class representing an authentication source.
 */

public final class AuthenticationSource
        implements Comparable<AuthenticationSource> {

    /**
     * The name parameter.
     */

    public static final String NAME_PARAMETER = "sourceName";

    /**
     * The JAAS type parameter.
     */

    public static final String JAAS_TYPE_PARAMETER = "jaasType";

    /**
     * The name for the default source.
     */

    public static final String DEFAULT_SOURCE_NAME = "The EPS";

    /**
     * The ID for the default source.
     */

    public static final String DEFAULT_SOURCE_ID = "0";

    /**
     * The default authentication source (The EPS DATABASE).
     */

    public static final AuthenticationSource DEFAULT_SOURCE =
        new AuthenticationSource(
            DEFAULT_SOURCE_ID, DEFAULT_SOURCE_NAME,
            EPSJAASConfiguration.DATABASE_APPLICATION_CONFIGURATION, null
        );

    /**
     * The id for this authentication source.
     */

    private String sourceId;

    /**
     * The name of this authentication source.
     */

    private String name;

    /**
     * The authentication source type for JAAS.
     */

    private String jaasType;

    /**
     * The miscellaneous properties associated with this auth source.
     */

    private Map<String,String> properties;

    /**
     * The module associated with this source.
     */
    
    private AuthenticationSourceModule module;
    
    /**
     * Constructor. Stores supplied information.
     *
     * @param newName The name of the authentication source.
     * @param newJaasType The jaasType for the information.
     * @param newProperties The properties associated with the source.
     */

    public AuthenticationSource(final String newName, final String newJaasType,
            final Map<String,String> newProperties) {
        this(null, newName, newJaasType, newProperties);
    }

    /**
     * Constructor. Stores supplied information.
     *
     * @param newSourceId The ID of the source (supplying null will generate a new,
     *            unique ID).
     * @param newName The name of the authentication source.
     * @param newJaasType The jaasType for the information.
     * @param newProperties The properties associated with the source.
     */

    public AuthenticationSource(final String newSourceId, final String newName,
            final String newJaasType, final Map<String,String> newProperties) {
        sourceId = newSourceId;
        if (sourceId == null) {
            sourceId = IDGenerator.getID();
        }
        name = newName;
        jaasType = newJaasType;
        properties = newProperties;
    }

    /**
     * Constructor. Extracts the relevant information from a Map.
     *
     * @param newSourceId The ID of the source to construct.
     * @param map The Map holding the data.
     */

    public AuthenticationSource(final String newSourceId, final Map<String,String> map) {
        sourceId = newSourceId;
        setProperties(map);
    }

    /**
     * Gets a specific property of this authentication source.
     *
     * @param propertyName The name of the property to get.
     *
     * @return The property value.
     */

    public Object get(final String propertyName) {
    	if( properties == null )
    		return null;
    	
        return properties.get(propertyName);
    }

    /**
     * Gets the properties Map object for this authenication source.
     *
     * @return The properties Map.
     */

    public Map<String,String> getProperties() {
        return properties;
    }

    /**
     * Overrides the current properties Map with a new one.
     *
     * @param map The new properties Map to use.
     */

    public void setProperties(final Map<String,String> map) {
        String testName = map.remove(NAME_PARAMETER);
        if (testName != null) {
            name = testName;
        }

        String testJaasType = map.remove(JAAS_TYPE_PARAMETER);
        if (testJaasType != null) {
            jaasType = testJaasType;
        }

        properties = map;
    }

    /**
     * Get the ID for this authentication source.
     *
     * @return The ID for the authentication source.
     */

    public String getSourceId() {
        return this.sourceId;
    }

    /**
     * Get the JAAS type for this authentication source.
     *
     * @return The JAAS type for this authentication source.
     */

    public String getJaasType() {
        return jaasType;
    }

    /**
     * Get the authentication source module associated with this source.
     */
    
    private AuthenticationSourceModule getModule() {
    	if( module != null )
    		return module;
    	
    	synchronized(this) {
        	if( module == null ) {
            	String type = getJaasType();
                switch (type) {
                    case EPSJAASConfiguration.LDAP_APPLICATION_CONFIGURATION:
                        module = new LDAPLoginModule();
                        break;
                    case EPSJAASConfiguration.RFC2307_APPLICATION_CONFIGURATION:
                        module = new JndiLoginModuleDummy();
                        break;
                    case EPSJAASConfiguration.LDAP_SANDB_APPLICATION_CONFIGURATION:
                        module = new LDAPSearchAndBindLoginModule();
                        break;
                    case EPSJAASConfiguration.AD_APPLICATION_CONFIGURATION:
                        module = new ActiveDirectoryLoginModule();
                        break;
                    case EPSJAASConfiguration.AD_NONANON_APPLICATION_CONFIGURATION:
                        module = new ActiveDirectoryNonAnonymousLoginModule();
                        break;
                    case EPSJAASConfiguration.AD_DOMAIN_APPLICATION_CONFIGURATION:
                        module = new ActiveDirectoryDomainLoginModule();
                        break;
                }
        	}
    	}
    	
		return module;
    }
    
    /**
     * Get the configuration options for this authentication source.
     * 
     * @return The AuthenticationSourceModule for this authentication source.
     */
    
    public Set<AuthenticationSourceConfigurationOption> getSourceOptions() {
    	AuthenticationSourceModule authModule = getModule();
    	Set<AuthenticationSourceConfigurationOption> options = authModule.getConfigurationOptions();
    	for(AuthenticationSourceConfigurationOption option : options) {
    		String key = option.getInternalName();
    		String value = (String)get(key);
    		if(value != null) {
    			option.setValue(value);
    		}
    	}
        return options;    	
    }
    
    /**
     * Get the configuration notes for this authentication source.
     * 
     * @return The configuration notes for this authentication source.
     */
    
    public String getSourceNotes() {
    	AuthenticationSourceModule authModule = getModule();
        return authModule.getConfigurationNotes();    	
    }
    
    /**
     * Get the name for this authentication source.
     *
     * @return The name of this authentication source.
     */

    public String getName() {
        return name;
    }

    /**
     * Sets the name for the authentication source.
     *
     * @param newName The new name for the authentication source.
     */

    public void setName(final String newName) {
        name = newName;
    }

    /**
     * Compare to another authentication source
     */
	@Override
	public int compareTo(AuthenticationSource arg0) {
		return name.compareTo(arg0.name);
	}
}
