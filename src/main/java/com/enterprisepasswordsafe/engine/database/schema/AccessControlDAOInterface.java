package com.enterprisepasswordsafe.engine.database.schema;

import com.enterprisepasswordsafe.engine.database.*;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;

public interface AccessControlDAOInterface<T extends EntityWithAccessRights, U extends AccessControl> {
    U create(T entity, AccessControledObject object, boolean allowRead, boolean allowModify)
            throws SQLException, UnsupportedEncodingException, GeneralSecurityException;
    void update(T entity, U accessControl)
            throws SQLException, UnsupportedEncodingException, GeneralSecurityException;
}
