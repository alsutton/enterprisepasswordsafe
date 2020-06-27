package com.enterprisepasswordsafe.database;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

public abstract class AbstractAccessRoleDAO<T> {

    private final String getAllSql;
    private final String getIndividualSql;
    private final String deleteSql;

    AbstractAccessRoleDAO(final String getAllSql, final String getIndividualSql, final String deleteSql) {
        this.getAllSql = getAllSql;
        this.getIndividualSql = getIndividualSql;
        this.deleteSql = deleteSql;
    }

    abstract T newInstanceForRole(String itemId, String actorId, String role);

    public T getByIds(final String itemId, final String actorId)
            throws SQLException {
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(getIndividualSql)) {
            ps.setString(1, itemId);
            ps.setString(2, actorId);
            ps.setMaxRows(1);
            try(ResultSet rs = ps.executeQuery()) {
                return rs.next() ? newInstanceForRole(itemId, actorId, rs.getString(1)) : null;
            }
        }
    }

    public Map<String,String> getAllForItem(final String id)
            throws SQLException {
        Map<String,String> results = new HashMap<>();
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(getAllSql)) {
            ps.setString(1, id);
            try(ResultSet rs = ps.executeQuery()) {
                while( rs.next() ) {
                    String actorId = rs.getString(1);
                    String role = rs.getString(2).intern();
                    results.put(actorId, role);
                }

                return results;
            }
        }
    }

    public void delete(final String itemId, final String actorId, final String role)
            throws SQLException {
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(deleteSql)) {
            ps.setString(1, itemId);
            ps.setString(2, actorId);
            ps.setString(3, role);
            ps.executeUpdate();
        }
    }

}
