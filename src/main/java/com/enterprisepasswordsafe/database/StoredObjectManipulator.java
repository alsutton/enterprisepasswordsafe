package com.enterprisepasswordsafe.database;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Base class which can be used for fetching otehr object types from the database.
 *
 * @param <T> The type of object being fetched
 */
abstract class StoredObjectManipulator<T>
    extends StoredObjectFetcher<T> {

    private String getByIdSql;

    private String getByNameSql;

    private String getCountSql;

    StoredObjectManipulator(final String getByIdSql, final String getByNameSql, final String getCountSql) {
        this.getByIdSql = getByIdSql;
        this.getByNameSql = getByNameSql;
        this.getCountSql = getCountSql;
    }

    public T getById(final String id)
            throws SQLException {
        return fetchObjectIfExists(getByIdSql, id);
    }

    public T getByName(final String name)
            throws SQLException {
        return fetchObjectIfExists(getByNameSql, name);
    }

    List<String> getFieldValues(final String sql, final String... parameters)
            throws SQLException {
        List<String> results = new ArrayList<>();
        try (PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(sql)) {
            setParameters(ps, parameters);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    try {
                        results.add(rs.getString(1));
                    } catch(Exception e) {
                        Logger.getAnonymousLogger().log(Level.SEVERE, "Error fetching object.", e);
                    }
                }
            }
        }
        return results;
    }

    public int countActiveUsers( )
            throws SQLException {
        try (Statement statement = BOMFactory.getCurrentConntection().createStatement()) {
            try(ResultSet rs = statement.executeQuery(getCountSql)) {
                return rs.next() ? rs.getInt(1) : 0;
            }
        }
    }
}
