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

package com.enterprisepasswordsafe.database.dbpool;

import com.enterprisepasswordsafe.engine.Repositories;
import com.enterprisepasswordsafe.engine.configuration.JDBCConnectionInformation;

import java.security.GeneralSecurityException;
import java.sql.SQLException;

public class DatabasePoolFactory {

    private static DatabasePool mSharedInstance;

    private void initialise(final JDBCConnectionInformation configuration)
        throws SQLException, ClassNotFoundException {
    	if(mSharedInstance != null) {
            mSharedInstance.close();
    	}

        mSharedInstance = new DatabasePool(configuration);
    }

    public synchronized void setConfiguration(JDBCConnectionInformation configuration)
            throws SQLException, ClassNotFoundException {
        if (mSharedInstance != null && mSharedInstance.isUsingConfiguration(configuration)) {
            return;
        }

        initialise(configuration);
    }

    public synchronized DatabasePool getInstance()
            throws SQLException, ClassNotFoundException, GeneralSecurityException {
        if(mSharedInstance == null) {
            setConfiguration(Repositories.jdbcConfigurationRepository.load());
        }
        return mSharedInstance;
    }

    public boolean isConfigured() {
        return mSharedInstance != null && mSharedInstance.isConfigured();
    }
}
