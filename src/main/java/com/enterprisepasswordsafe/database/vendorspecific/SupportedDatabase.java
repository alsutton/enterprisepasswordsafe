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

package com.enterprisepasswordsafe.database.vendorspecific;

import com.enterprisepasswordsafe.database.vendorspecific.implementations.*;

public enum SupportedDatabase {
    APACHE_DERBY ("Apache Derby", ApacheDerbyDAL.class, false),
    DB2("DB2", Db2DAL.class, false),
    HSQLDB("HSQLDB", HsqldbDAL.class, true),
    MYSQL("MySQL", MysqlDAL.class, false),
    ORACLE("Oracle", OracleDAL.class, false),
    POSTGRESQL("PostgreSQL", PostgresqlDAL.class, false),
    SQLSERVER("SQL Server", SqlserverDAL.class, false),
    SQLSERVER_2000("SQL Server 2000", SqlserverDAL.class, true),
    SQLSERVER_2005("SQL Server 2005", SqlserverDAL.class, true),
    OTHER("Other", GenericDAL.class, false);

    private final String mType;
    private final Class<? extends DALInterface> mDalClass;
    private final boolean mIsDeprecated;

    SupportedDatabase(final String type, final Class<? extends DALInterface> dalClass,
                      final boolean isDeprecated) {
        mType = type;
        mDalClass = dalClass;
        mIsDeprecated = isDeprecated;
    }

    public String getType() {
        return mType;
    }

    public Class<? extends DALInterface> getDALClass() {
        return mDalClass;
    }

    public boolean isSupportDeprecated() {
        return mIsDeprecated;
    }

}
