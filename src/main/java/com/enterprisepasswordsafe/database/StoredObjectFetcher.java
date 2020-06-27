package com.enterprisepasswordsafe.database;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public abstract class StoredObjectFetcher<T>
    extends JDBCBase {

    abstract T newInstance(ResultSet rs, int startIndex) throws SQLException;

    T fetchObjectIfExists(String sql, final String... parameters)
            throws SQLException {
        if (sql == null) {
            throw new RuntimeException("Unsupported operation");
        }
        try(PreparedStatement ps =  BOMFactory.getCurrentConntection().prepareStatement(sql)) {
            setParameters(ps, parameters);
            ps.setMaxRows(1);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? newInstance(rs, 1) : null;
            }
        }
    }


    List<T> getMultiple(final String sql, final String... parameters)
            throws SQLException {
        List<T> results = new ArrayList<>();
        try (PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(sql)) {
            setParameters(ps, parameters);
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
}
