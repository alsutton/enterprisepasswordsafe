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

package com.enterprisepasswordsafe.engine.jaas;

import com.enterprisepasswordsafe.proguard.ExternalInterface;

import java.util.HashMap;
import java.util.Map;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;

// import com.sun.security.auth.module.JndiLoginModule;

/**
 * Object responsible for ensuring the correct JAAS setting is used for
 * an authentication source.
 */
public final class EPSJAASConfiguration extends Configuration implements ExternalInterface {

    /**
     * The value set to use the database as an authentication source.
     */

    public static final String DATABASE_APPLICATION_CONFIGURATION = "Database";

    /**
     * The value set to use Active Directory authentication source.
     */

    public static final String AD_APPLICATION_CONFIGURATION = "AD";

    /**
     * The value set to use Active Directory (Non-Anonymous) authentication source.
     */

    public static final String AD_NONANON_APPLICATION_CONFIGURATION = "AD_NONANON";

    /**
     * The value set to use Active Directory (Domain) authentication source.
     */

    public static final String AD_DOMAIN_APPLICATION_CONFIGURATION = "AD_DOMAIN";

    /**
     * The value set to use an LDAP bind as an authentication source.
     */

    public static final String LDAP_APPLICATION_CONFIGURATION = "LDAPBind";

    /**
     * The value set to use LDAP search and bind as an authentication source.
     */

    public static final String LDAP_SANDB_APPLICATION_CONFIGURATION = "LDAPSandB";

    /**
     * The value set to use the and RFC2307 store as an authentication source.
     */

    public static final String RFC2307_APPLICATION_CONFIGURATION = "RFC2307";

    /**
     * The AppConfigEntry array for database authentication.
     */

    private static final AppConfigurationEntry[] DATABASE_AUTH_CONFIGURATION =
            {new AppConfigurationEntry(
            DatabaseLoginModule.class.getName(),
            AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
            new HashMap<String,String>()) };

    /**
     * The properties for this configuration module.
     */

    private Map<String,String> properties;

    /**
     * Constructor. Allows parameters to be passed.
     *
     * @param newProperties The properties to use.
     */

    public EPSJAASConfiguration(final Map<String,String> newProperties) {
        properties = newProperties;
    }

    /**
     * Refresh this configuration. Nothing is needed, but the
     * method needs to be implemented due to the Configuration
     * base class.
     */
    public void refresh() {
    }

    /**
     * Get the configuration for a particular application.
     *
     * @param applicationName The name of the application which provides
     *  authentication information.
     *
     * @return Thr configuration entries relevant to the application.
     */
    public AppConfigurationEntry[] getAppConfigurationEntry(final String applicationName) {
        if (applicationName
                .equals(EPSJAASConfiguration.DATABASE_APPLICATION_CONFIGURATION)) {
            return EPSJAASConfiguration.DATABASE_AUTH_CONFIGURATION;
        } else if (applicationName
                .equals(EPSJAASConfiguration.LDAP_APPLICATION_CONFIGURATION)) {
            AppConfigurationEntry[] entries = new AppConfigurationEntry[1];
            entries[0] = new AppConfigurationEntry(
                    LDAPLoginModule.class.getName(),
                    AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                    properties);
            return entries;
        } else if (applicationName
                .equals(EPSJAASConfiguration.RFC2307_APPLICATION_CONFIGURATION)) {
// TODO: JNDILoginModule
        	AppConfigurationEntry[] entries = new AppConfigurationEntry[1];
//            entries[0] = new AppConfigurationEntry(
//                    JndiLoginModule.class.getName(),
//                    AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
//                    properties);
            return entries;
        } else if (applicationName
                .equals(EPSJAASConfiguration.LDAP_SANDB_APPLICATION_CONFIGURATION)) {
            AppConfigurationEntry[] entries = new AppConfigurationEntry[1];
            entries[0] = new AppConfigurationEntry(
                    LDAPSearchAndBindLoginModule.class.getName(),
                    AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                    properties);
            return entries;
        } else if (applicationName
                .equals(EPSJAASConfiguration.AD_APPLICATION_CONFIGURATION)) {
            AppConfigurationEntry[] entries = new AppConfigurationEntry[1];
            entries[0] = new AppConfigurationEntry(
                    ActiveDirectoryLoginModule.class.getName(),
                    AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                    properties);
            return entries;
        } else if (applicationName
	            .equals(EPSJAASConfiguration.AD_NONANON_APPLICATION_CONFIGURATION)) {
	        AppConfigurationEntry[] entries = new AppConfigurationEntry[1];
	        entries[0] = new AppConfigurationEntry(
	                ActiveDirectoryNonAnonymousLoginModule.class.getName(),
	                AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
	                properties);
	        return entries;
	    }	else if (applicationName
	            .equals(EPSJAASConfiguration.AD_DOMAIN_APPLICATION_CONFIGURATION)) {
	        AppConfigurationEntry[] entries = new AppConfigurationEntry[1];
	        entries[0] = new AppConfigurationEntry(
	                ActiveDirectoryDomainLoginModule.class.getName(),
	                AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
	                properties);
	        return entries;
	    }
        return new AppConfigurationEntry[0];
    }
}
