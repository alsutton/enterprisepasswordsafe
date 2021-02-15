package com.enterprisepasswordsafe.model.dao;

import com.enterprisepasswordsafe.accesscontrol.AbstractAccessControl;
import com.enterprisepasswordsafe.model.EntityWithName;
import com.enterprisepasswordsafe.model.PasswordPermission;
import com.enterprisepasswordsafe.model.persisted.Password;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;

public interface AccessControlDAOInterface<T extends EntityWithName, U extends AbstractAccessControl> {
    U create(T entity, Password object, PasswordPermission permission)
            throws SQLException, UnsupportedEncodingException, GeneralSecurityException;
    void store(T entity, U accessControl)
            throws SQLException, GeneralSecurityException;
    U get(T entity, Password item) throws SQLException, GeneralSecurityException;
}
