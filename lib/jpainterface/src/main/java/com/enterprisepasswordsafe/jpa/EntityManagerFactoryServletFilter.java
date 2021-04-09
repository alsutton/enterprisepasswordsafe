package com.enterprisepasswordsafe.jpa;

import com.enterprisepasswordsafe.configuration.EnvironmentVariableBackedJDBCConfigurationRepository;
import com.enterprisepasswordsafe.configuration.JDBCConnectionInformation;

import javax.persistence.EntityManagerFactory;
import javax.persistence.Persistence;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;

@WebFilter("/")
public class EntityManagerFactoryServletFilter implements Filter {
    static final String ENTITY_MANAGER_FACTORY_ATTRIBUTE = "_entityManagerFactory";
    static final String CLEAR_ENTITY_MANAGER_FACTORY_ATTRIBUTE = "_entityManagerFactory_clear";

    private final Supplier<JDBCConnectionInformation> connectionInformationProvider;
    private final Object entityManagerFactoryGuard = new Object();

    private EntityManagerFactory entityManagerFactory = null;

    public EntityManagerFactoryServletFilter() {
        connectionInformationProvider = new EnvironmentVariableBackedJDBCConfigurationRepository();
    }

    EntityManagerFactoryServletFilter(Supplier<JDBCConnectionInformation> connectionInformationProvider) {
        this.connectionInformationProvider = connectionInformationProvider;
    }

    @Override
    public void init(FilterConfig filterConfig) {
        initialiseEntityManagerFactory();
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (entityManagerFactory == null) {
            initialiseEntityManagerFactory();
        }

        if (entityManagerFactory != null) {
            request.setAttribute(ENTITY_MANAGER_FACTORY_ATTRIBUTE, entityManagerFactory);
        }

        chain.doFilter(request, response);

        if (request.getAttribute(CLEAR_ENTITY_MANAGER_FACTORY_ATTRIBUTE) != null) {
            destroy();
        }
    }

    @Override
    public void destroy() {
        synchronized (entityManagerFactoryGuard) {
            if(entityManagerFactory != null && entityManagerFactory.isOpen()) {
                entityManagerFactory.close();
                entityManagerFactory = null;
            }
        }
    }

    private void initialiseEntityManagerFactory() {
        synchronized (entityManagerFactoryGuard) {
            if (entityManagerFactory != null) {
                return;
            }

            JDBCConnectionInformation connectionInformation = connectionInformationProvider.get();
            if (initialiseDriver(connectionInformation)) {
                Map<String, String> properties = convertToEntityManagerProperties(connectionInformation);
                entityManagerFactory =
                        Persistence.createEntityManagerFactory(
                                "com.enterprisepasswordsafe",
                                properties);
            }
        }
    }

    private boolean initialiseDriver(JDBCConnectionInformation connectionInformation) {
        if (connectionInformation == null) {
            return false;
        }

        String driverClass = connectionInformation.getDriver();
        if (driverClass == null || driverClass.isBlank()) {
            return false;
        }

        try {
            Class.forName(connectionInformation.getDriver());
            return true;
        } catch (ClassNotFoundException e) {
            Logger.getAnonymousLogger().log(Level.WARNING, "Unable to initialise database driver", e);
        }

        return false;
    }

    private Map<String,String> convertToEntityManagerProperties(JDBCConnectionInformation connectionInformation) {
        Map<String,String> properties = new HashMap<>();
        properties.put("hibernate.connection.url", connectionInformation.getUrl());
        properties.put("hibernate.connection.username", connectionInformation.getUsername());
        properties.put("hibernate.connection.password", connectionInformation.getPassword());
        return properties;
    }
}
