package com.enterprisepasswordsafe.model;

import com.enterprisepasswordsafe.model.dao.AccessRoleDAO;
import com.enterprisepasswordsafe.model.dao.AuthenticationSourceDAO;
import com.enterprisepasswordsafe.model.dao.ConfigurationDAO;
import com.enterprisepasswordsafe.model.dao.GroupDAO;
import com.enterprisepasswordsafe.model.dao.HierarchyNodeAccessRuleDAO;
import com.enterprisepasswordsafe.model.dao.HierarchyNodeDAO;
import com.enterprisepasswordsafe.model.dao.HierarchyNodePermissionDAO;
import com.enterprisepasswordsafe.model.dao.IntegrationModuleDAO;
import com.enterprisepasswordsafe.model.dao.LocationDAO;
import com.enterprisepasswordsafe.model.dao.LoggingDAO;
import com.enterprisepasswordsafe.model.dao.MembershipDAO;
import com.enterprisepasswordsafe.model.dao.PasswordAccessControlDAO;
import com.enterprisepasswordsafe.model.dao.UserDAO;

import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;

public class DAORepository implements AutoCloseable {

    private final EntityManager entityManager;

    public DAORepository(EntityManagerFactory entityManagerFactory) {
        this.entityManager = entityManagerFactory.createEntityManager();
    }

    public AccessRoleDAO getAccessRoleDAO() {
        return new AccessRoleDAO(this, entityManager);
    }

    public AuthenticationSourceDAO getAuthenticationSourceDAO() {
        return new AuthenticationSourceDAO(this, entityManager);
    }

    public ConfigurationDAO getConfigurationDAO() {
        return new ConfigurationDAO(this, entityManager);
    }

    public GroupDAO getGroupDAO() {
        return new GroupDAO(this, entityManager);
    }

    public HierarchyNodeDAO getHierarchyNodeDAO() {
        return new HierarchyNodeDAO(this, entityManager);
    }

    public HierarchyNodeAccessRuleDAO getHierarchyNodeAccessRuleDAO() {
        return new HierarchyNodeAccessRuleDAO(this, entityManager);
    }

    public HierarchyNodePermissionDAO getHierarchyNodePermissionDAO() {
        return new HierarchyNodePermissionDAO(this, entityManager);
    }

    public IntegrationModuleDAO getIntegrationModuleDAO() {
        return new IntegrationModuleDAO(this, entityManager);
    }
    public LocationDAO getLocationDAO() { return new LocationDAO(this, entityManager); }

    public LoggingDAO getLoggingDAO() { return new LoggingDAO(this, entityManager); }

    public MembershipDAO getMembershipDAO() {
        return new MembershipDAO(this, entityManager);
    }

    public PasswordAccessControlDAO getPasswordAccessControlDAO() {
        return new PasswordAccessControlDAO(this, entityManager);
    }

    public UserDAO getUserDAO() { return new UserDAO(this, entityManager); }

    @Override
    public void close() throws Exception {
        if(entityManager != null && entityManager.isOpen()) {
            entityManager.close();
        }
    }
}
