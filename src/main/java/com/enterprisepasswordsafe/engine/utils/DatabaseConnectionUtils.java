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

package com.enterprisepasswordsafe.engine.utils;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Utility class for handling JDBC objects.
 */
public final class DatabaseConnectionUtils {

    /**
     * Private constructor to avoid instanciation by other classes.
     */

    private DatabaseConnectionUtils() { }

    /**
     * Closes a PreparedStatement without throwing an exception.
     *
     * @param stmt
     *            The PreparedStatement to close.
     */

    public static void close(final Statement stmt) {
        if (stmt == null) {
            return;
        }

        try {
            stmt.close();
        } catch (Exception excpt) {
            Logger.getLogger(DatabaseConnectionUtils.class.getName()).log(Level.WARNING, "Error closing Statement", excpt);
        }
    }

    /**
     * Closes a ResulSet without throwing an exception.
     *
     * @param rs
     *            The PreparedStatement to close.
     */

    public static void close(final ResultSet rs) {
        if (rs == null) {
            return;
        }

        try {
            rs.close();
        } catch (Exception excpt) {
            Logger.getLogger(DatabaseConnectionUtils.class.getName()).log(Level.WARNING, "Error closing ResultSet", excpt);
        }
    }

    /**
     * Closes a Connection without throwing an exception.
     *
     * @param conn
     *            The Connection to close.
     */

    public static void close(final Connection conn) {
        if (conn == null) {
            return;
        }

        try {
            conn.close();
        } catch (Exception excpt) {
            Logger.getLogger(DatabaseConnectionUtils.class.getName()).log(Level.WARNING, "Error closing Connection", excpt);
        }
    }

}
