package com.enterprisepasswordsafe.database;

import com.enterprisepasswordsafe.engine.AccessControlDecryptor;

import java.security.GeneralSecurityException;
import java.sql.SQLException;

public interface EntityWithAccessRightsDAO<T extends EntityWithAccessRights, D extends AccessControlDecryptor> {

    T getByIdDecrypted(String id, D decrypter) throws SQLException, GeneralSecurityException;
}
