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

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import java.util.HashMap;
import java.util.Map;

public final class EPSJAASConfiguration extends Configuration {

    public static final String DATABASE_APPLICATION_CONFIGURATION = "Database";

    public static final String AD_APPLICATION_CONFIGURATION = "AD";

    public static final String AD_NONANON_APPLICATION_CONFIGURATION = "AD_NONANON";

    public static final String AD_DOMAIN_APPLICATION_CONFIGURATION = "AD_DOMAIN";

    public static final String LDAP_APPLICATION_CONFIGURATION = "LDAPBind";

    public static final String LDAP_SANDB_APPLICATION_CONFIGURATION = "LDAPSandB";

    public static final String RFC2307_APPLICATION_CONFIGURATION = "RFC2307";

    private static final AppConfigurationEntry[] DATABASE_AUTH_CONFIGURATION = {
            new AppConfigurationEntry(DatabaseLoginModule.class.getName(),
                    AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, new HashMap<String,String>()) };

    private static final Map<String, String> APP_NAME_TO_CLASS_MAP;
    static {
        APP_NAME_TO_CLASS_MAP = new HashMap<>();
        APP_NAME_TO_CLASS_MAP.put(EPSJAASConfiguration.AD_DOMAIN_APPLICATION_CONFIGURATION,
                ActiveDirectoryDomainLoginModule.class.getName());
        APP_NAME_TO_CLASS_MAP.put(EPSJAASConfiguration.AD_NONANON_APPLICATION_CONFIGURATION,
                ActiveDirectoryNonAnonymousLoginModule.class.getName());
        APP_NAME_TO_CLASS_MAP.put(EPSJAASConfiguration.AD_APPLICATION_CONFIGURATION,
                ActiveDirectoryLoginModule.class.getName());
        APP_NAME_TO_CLASS_MAP.put(EPSJAASConfiguration.LDAP_SANDB_APPLICATION_CONFIGURATION,
                LDAPSearchAndBindLoginModule.class.getName());
        APP_NAME_TO_CLASS_MAP.put(EPSJAASConfiguration.LDAP_APPLICATION_CONFIGURATION,
                LDAPLoginModule.class.getName());

    }

    private Map<String,String> properties;

    public EPSJAASConfiguration(final Map<String,String> newProperties) {
        properties = newProperties;
    }

    public void refresh() {
    }

    public AppConfigurationEntry[] getAppConfigurationEntry(final String applicationName) {
        if (applicationName.equals(EPSJAASConfiguration.DATABASE_APPLICATION_CONFIGURATION)) {
            return EPSJAASConfiguration.DATABASE_AUTH_CONFIGURATION;
        }

        String className = APP_NAME_TO_CLASS_MAP.get(applicationName);
        if(className == null) {
            return new AppConfigurationEntry[0];
        }

        return getAppConfigurationEntriesFor(className);
    }

    private AppConfigurationEntry[] getAppConfigurationEntriesFor(String provider) {
        AppConfigurationEntry[] entries = new AppConfigurationEntry[1];
        entries[0] =  new AppConfigurationEntry(provider, AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, properties);
        return entries;
    }
}
