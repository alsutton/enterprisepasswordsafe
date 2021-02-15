package com.enterprisepasswordsafe.model.dao;

import com.enterprisepasswordsafe.model.DAORepository;
import com.enterprisepasswordsafe.model.persisted.GroupAccessRole;

import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.TypedQuery;

public class JPADAOBase<T> {
    protected final DAORepository daoRepository;
    protected final EntityManager entityManager;
    private   final Class<T> objectClass;

    protected JPADAOBase(DAORepository daoRepository, EntityManager entityManager,
                         Class<T> objectClass) {
        this.daoRepository = daoRepository;
        this.entityManager = entityManager;
        this.objectClass = objectClass;
    }

    public T getById(Object id) {
        return entityManager.find(objectClass, id);
    }

    public void store(T instance) {
        entityManager.persist(instance);
    }

    public void delete(T instance) {
        entityManager.detach(instance);
    }

    /**
     * Gets the result of a named query which returns a single result of the type the DAO
     * relates to.
     *
     * @param queryName The named query to execute.
     * @param parameterName The name of the parameter for the query.
     * @param value The value for the parameter.
     * @return The single object matching the query, or null if no matching object was found.
     */
    public T getWithSingleParameter(String queryName, String parameterName, Object value) {
        TypedQuery<T> query = entityManager.createNamedQuery(queryName, objectClass);
        query.setParameter(parameterName, value);
        try {
            return query.getSingleResult();
        } catch (NoResultException e) {
            return null;
        }
    }
}
