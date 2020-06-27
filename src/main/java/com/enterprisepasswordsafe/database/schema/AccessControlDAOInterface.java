package com.enterprisepasswordsafe.database.schema;

import com.enterprisepasswordsafe.database.AccessControledObject;
import com.enterprisepasswordsafe.database.EntityWithAccessRights;
import com.enterprisepasswordsafe.engine.accesscontrol.AccessControl;
import com.enterprisepasswordsafe.engine.accesscontrol.PasswordPermission;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;

public interface AccessControlDAOInterface<T extends EntityWithAccessRights, U extends AccessControl> {
    U create(T entity, AccessControledObject object, PasswordPermission permission)
            throws SQLException, UnsupportedEncodingException, GeneralSecurityException;
    void update(T entity, U accessControl)
            throws SQLException, UnsupportedEncodingException, GeneralSecurityException;
}
