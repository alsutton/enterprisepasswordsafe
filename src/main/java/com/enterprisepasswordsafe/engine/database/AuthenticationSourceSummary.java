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

/*
 * Summary for an authentication source.
 */
package com.enterprisepasswordsafe.engine.database;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import com.enterprisepasswordsafe.engine.utils.DatabaseConnectionUtils;


/**
 * Summary class. Holds only the source name and ID
 */

public final class AuthenticationSourceSummary {

    /**
     * The SQL to get all of the summaries.
     */

    private static final String GET_ALL_SUMMARIES = "SELECT source_id, param_value "
            + "  FROM auth_sources "
            + " WHERE param_name = '"
            + AuthenticationSource.NAME_PARAMETER + "'";

    /**
     * The ID for this source.
     */

    private String id;

    /**
     * The name for this source.
     */

    private String source;

    /**
     * Private constructor. Summaries should only come from the database via the
     * methods in this object.
     *
     * @param rs The result set to extract the data.
     *
     * @throws SQLException
     *             Thrown if there is a problem extracting the data from the
     *             result set.
     */

    private AuthenticationSourceSummary(final ResultSet rs)
        throws SQLException {
        int idx = 1;
        id = rs.getString(idx++);
        source = rs.getString(idx);
    }

    /**
     * Obtain a human readable form of the summary.
     *
     * @return A String representation of the object.
     */

    public String toString() {
        StringBuffer buffer = new StringBuffer(id.length() + source.length());
        buffer.append(source);
        buffer.append(" (");
        buffer.append(id);
        buffer.append(')');
        return buffer.toString();
    }

    /**
     * Gets the summaries for all of the sources.
     *
     * @param conn
     *            The connection to the database.
     *
     * @return A List of Summary objects holding the details about each source.
     *
     * @throws SQLException
     *             Thrown if there is a problem extracting the data from the
     *             database
     */

    public static List<AuthenticationSourceSummary> getAll(final Connection conn)
        throws SQLException {
        List<AuthenticationSourceSummary> summaries = new ArrayList<AuthenticationSourceSummary>();
        try(Statement stmt = conn.createStatement()) {
            try(ResultSet rs = stmt.executeQuery(AuthenticationSourceSummary.GET_ALL_SUMMARIES)) {
                while (rs.next()) {
                    summaries.add(new AuthenticationSourceSummary(rs));
                }
            }
        }
        return summaries;
    }

    /**
     * Get the ID for this source.
     *
     * @return The ID for this source.
     */

    public String getId() {
        return id;
    }

    /**
     * Get the authentication source.
     *
     * @return The authentication source.
     */
    public String getName() {
        return source;
    }
}
