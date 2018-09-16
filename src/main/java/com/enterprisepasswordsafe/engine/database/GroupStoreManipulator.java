package com.enterprisepasswordsafe.engine.database;

import com.enterprisepasswordsafe.engine.utils.DatabaseConnectionUtils;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public abstract class GroupStoreManipulator extends StoredObjectManipulator<Group> {

    static final String GROUP_FIELDS = " grp.group_id, grp.group_name, grp.status ";

    private static final String UPDATE_GROUP_SQL = "UPDATE groups SET group_name = ?, status = ? WHERE group_id = ?";

    private static final String DELETE_SQL = "UPDATE groups SET status = "+Group.STATUS_DELETED+" WHERE group_id = ?",
                                DELETE_GAC_SQL = "DELETE FROM group_access_control WHERE group_id = ?",
                                DELETE_MEMBERSHIP_SQL = "DELETE FROM membership WHERE group_id = ?";

    private static final String[] DELETE_SQL_STATEMENTS = { DELETE_SQL, DELETE_GAC_SQL, DELETE_MEMBERSHIP_SQL };

    GroupStoreManipulator(String getByIdSql, String getByNameSql, String getCountSql) {
        super(getByIdSql, getByNameSql, getCountSql);
    }

    @Override
    Group newInstance(ResultSet rs, int startIndex)
            throws SQLException {
        return new Group(rs, startIndex);
    }

    public void update(final Group group)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(UPDATE_GROUP_SQL)) {
            ps.setString(1, group.getGroupName());
            ps.setInt(2, group.getStatus());
            ps.setString(3, group.getGroupId());
            ps.executeUpdate();
        }
    }

    public void delete( final Group group )
            throws SQLException {
        String theGroupId = group.getGroupId();
        for(String sql: DELETE_SQL_STATEMENTS) {
            runResultlessParameterisedSQL(sql, theGroupId);
        }
    }
}
