/*
 * Copyright (c) 2017 Carbon Security Ltd. <opensource@carbonsecurity.co.uk>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package com.enterprisepasswordsafe.engine.database;

import com.enterprisepasswordsafe.engine.configuration.JDBCConfiguration;
import com.enterprisepasswordsafe.engine.database.User;
import com.enterprisepasswordsafe.engine.database.UserDAO;
import com.enterprisepasswordsafe.engine.dbabstraction.SupportedDatabase;
import com.enterprisepasswordsafe.engine.dbpool.DatabasePool;
import com.enterprisepasswordsafe.engine.dbpool.DatabasePoolFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.mockito.BDDMockito;
import org.powermock.api.mockito.PowerMockito;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.sql.SQLException;

import static org.mockito.Mockito.when;

/**
 * Utilities to set up and access an in-memory database for testing purposes.
 */
public class EmbeddedDatabaseTestBase {

    @BeforeClass
    public static void initialise()
            throws SQLException, InstantiationException, IllegalAccessException,
            ClassNotFoundException, IOException, GeneralSecurityException {
        JDBCConfiguration configuration = new JDBCConfiguration();
        configuration.setDatabaseType(SupportedDatabase.APACHE_DERBY.getType());
        configuration.setDriver("org.apache.derby.jdbc.EmbeddedDriver");
        configuration.setURL("jdbc:derby:memory:myDB;create=true");
        configuration.setPassword("");
        configuration.setUsername("");

        PowerMockito.mockStatic(JDBCConfiguration.class);
        BDDMockito.given(JDBCConfiguration.getConfiguration()).willReturn(configuration);

        DatabasePoolFactory.setConfiguration(configuration);
        DatabasePool pool = DatabasePoolFactory.getInstance();
        pool.initialiseDatabase();
    }

    /**
     * Get the admin user.
     */

    public User getAdminUser() throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        User admin = UserDAO.getInstance().getByName("admin");
        admin.decryptAccessKey("admin");
        return admin;
    }
}
