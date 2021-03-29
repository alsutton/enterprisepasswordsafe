package com.enterprisepasswordsafe.authentication;

import com.enterprisepasswordsafe.authentication.jaas.ActiveDirectoryDomainLoginModule;
import com.enterprisepasswordsafe.authentication.jaas.ActiveDirectoryLoginModule;
import com.enterprisepasswordsafe.authentication.jaas.ActiveDirectoryNonAnonymousLoginModule;
import com.enterprisepasswordsafe.authentication.jaas.AuthenticationSourceModule;
import com.enterprisepasswordsafe.authentication.jaas.EPSJAASConfiguration;
import com.enterprisepasswordsafe.authentication.jaas.JndiLoginModuleDummy;
import com.enterprisepasswordsafe.authentication.jaas.LDAPLoginModule;
import com.enterprisepasswordsafe.authentication.jaas.LDAPSearchAndBindLoginModule;
import com.enterprisepasswordsafe.model.persisted.AuthenticationSource;

public class AuthenticationModuleSupplier {

    public AuthenticationSourceModule getFor(AuthenticationSource source) {
        String type = source.getJaasType();
        switch (type) {
            case EPSJAASConfiguration.LDAP_APPLICATION_CONFIGURATION:
                return new LDAPLoginModule();
            case EPSJAASConfiguration.RFC2307_APPLICATION_CONFIGURATION:
                return new JndiLoginModuleDummy();
            case EPSJAASConfiguration.LDAP_SANDB_APPLICATION_CONFIGURATION:
                return new LDAPSearchAndBindLoginModule();
            case EPSJAASConfiguration.AD_APPLICATION_CONFIGURATION:
                return new ActiveDirectoryLoginModule();
            case EPSJAASConfiguration.AD_NONANON_APPLICATION_CONFIGURATION:
                return new ActiveDirectoryNonAnonymousLoginModule();
            case EPSJAASConfiguration.AD_DOMAIN_APPLICATION_CONFIGURATION:
                return new ActiveDirectoryDomainLoginModule();
            default:
                return null;
        }
    }
}
