package com.enterprisepasswordsafe.database;

import com.enterprisepasswordsafe.database.AccessControledObject;
import com.enterprisepasswordsafe.database.EntityWithAccessRights;
import com.enterprisepasswordsafe.database.Password;
import com.enterprisepasswordsafe.engine.accesscontrol.AccessControl;
import com.enterprisepasswordsafe.engine.accesscontrol.PasswordPermission;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;

public interface AccessControlDAOInterface<T extends EntityWithAccessRights, U extends AccessControl> {
    U create(T entity, AccessControledObject object, PasswordPermission permission)
            throws SQLException, UnsupportedEncodingException, GeneralSecurityException;
    void write(T entity, U accessControl)
            throws SQLException, GeneralSecurityException;
    void update(T entity, U accessControl)
            throws SQLException, GeneralSecurityException;
    U get(T entity, AccessControledObject item) throws SQLException, GeneralSecurityException;
}
