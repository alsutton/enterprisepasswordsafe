package com.enterprisepasswordsafe.engine.database;

import java.security.GeneralSecurityException;
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
abstract class ObjectFetcher<T> {

    private String getByIdSql;

    private String getByNameSql;

    private String getCountSql;

    ObjectFetcher(final String getByIdSql, final String getByNameSql, final String getCountSql) {
        this.getByIdSql = getByIdSql;
        this.getByNameSql = getByNameSql;
        this.getCountSql = getCountSql;
    }

    abstract T newInstance(ResultSet rs, int startIndex) throws SQLException;

    public T getById(final String id)
            throws SQLException {
        try (PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(getByIdSql)) {
            return fetchObjectIfExists(ps, id);
        }
    }

    public T getByName(final String name)
            throws SQLException {
        try(PreparedStatement ps =  BOMFactory.getCurrentConntection().prepareStatement(getByNameSql)) {
            return fetchObjectIfExists(ps, name);
        }
    }

    T fetchObjectIfExists(PreparedStatement ps, String parameter)
            throws SQLException {
        ps.setString(1, parameter);
        ps.setMaxRows(1);
        try(ResultSet rs = ps.executeQuery()) {
            return rs.next() ? newInstance(rs, 1) : null;
        }
    }



    List<T> getMultiple(final String sql, final String parameter)
            throws SQLException {
        List<T> results = new ArrayList<>();
        try (PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(sql)) {
            if (parameter != null) {
                ps.setString(1, parameter);
            }
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    try {
                        results.add(newInstance(rs, 1));
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
