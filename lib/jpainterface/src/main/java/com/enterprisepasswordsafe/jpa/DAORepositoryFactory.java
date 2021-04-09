package com.enterprisepasswordsafe.jpa;

import com.enterprisepasswordsafe.model.DAORepository;

import javax.persistence.EntityManagerFactory;
import javax.servlet.ServletRequest;

public class DAORepositoryFactory {
    public static DAORepository newInstance(ServletRequest request) {
        EntityManagerFactory entityManagerFactory =
                (EntityManagerFactory) request.getAttribute(
                        EntityManagerFactoryServletFilter.ENTITY_MANAGER_FACTORY_ATTRIBUTE);
        if(entityManagerFactory == null) {
            return null;
        }
        return new DAORepository(entityManagerFactory);
    }
}
