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

package com.enterprisepasswordsafe.database;

import com.enterprisepasswordsafe.engine.configuration.TestJDBCConfiguration;
import org.junit.jupiter.api.BeforeAll;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;


abstract class EmbeddedDatabaseTestBase {

    @BeforeAll
    public static void initialise()
            throws SQLException, InstantiationException, IllegalAccessException,
            ClassNotFoundException, IOException, GeneralSecurityException {
        TestJDBCConfiguration.forceTestingConfiguration();
    }

    /**
     * Get the admin user.
     */

    User getAdminUser() throws SQLException, GeneralSecurityException {
        User admin = UserDAO.getInstance().getByName("admin");
        admin.decryptAccessKey("admin");
        return admin;
    }
}
