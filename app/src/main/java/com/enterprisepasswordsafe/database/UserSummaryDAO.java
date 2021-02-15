package com.enterprisepasswordsafe.database;

import com.enterprisepasswordsafe.database.derived.AbstractUserSummary;
import com.enterprisepasswordsafe.database.derived.ImmutableUserSummary;
import com.enterprisepasswordsafe.engine.users.UserClassifier;
import com.enterprisepasswordsafe.engine.utils.Cache;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class UserSummaryDAO extends StoredObjectManipulator<AbstractUserSummary> {

    private static final String GET_SUMMARY_BY_ID =
            "SELECT   user_id, user_name, full_name "
                    + "  FROM application_users "
                    + " WHERE (disabled is null or disabled = 'N')"
                    + "   AND user_id = ? ";

    private static final String GET_SUMMARY_BY_NAME =
            "SELECT   user_id, user_name, full_name "
                    + "  FROM application_users "
                    + " WHERE (disabled is null or disabled = 'N')"
                    + "   AND user_name = ? ";

    private static final String GET_SUMMARY_BY_SEARCH =
            "SELECT   user_id, user_name, full_name "
                    + "  FROM application_users "
                    + " WHERE (disabled is null or disabled = 'N')"
                    + "   AND user_name like ? ";

    private static final String GET_SUMMARY_LIST_INCLUDING_ADMIN =
            "SELECT user_id, user_name, full_name "
                    + "  FROM application_users "
                    + " WHERE (disabled is null or disabled = 'N')"
                    + " ORDER BY user_name ASC";

    private static final String GET_SUMMARY_LIST_EXCLUDING_ADMIN =
            "SELECT user_id, user_name, full_name "
                    + "FROM application_users "
                    + "WHERE user_id <>  '" + UserClassifier.ADMIN_USER_ID +"' "
                    + "  AND (disabled is null or disabled = 'N')"
                    + "ORDER BY user_name ASC";

    public UserSummaryDAO() {
        super(GET_SUMMARY_BY_ID, GET_SUMMARY_BY_NAME, UserDAO.GET_COUNT_SQL);
    }

    @Override
    AbstractUserSummary newInstance(ResultSet rs) throws SQLException {
        return ImmutableUserSummary.builder()
                .id(rs.getString(1))
                .name(rs.getString(2))
                .fullName(rs.getString(3))
                .build();
    }

    public List<AbstractUserSummary> getSummaryList()
            throws SQLException {
        return getMultiple(GET_SUMMARY_LIST_INCLUDING_ADMIN);
    }

    public List<AbstractUserSummary> getSummaryListExcludingAdmin()
            throws SQLException {
        return getMultiple(GET_SUMMARY_LIST_EXCLUDING_ADMIN);
    }

    /**
     * Get a List of UserSummary objects representing the users returned by a query.
     *
     * @param searchQuery The query used to fetch the users.
     *
     * @return The summary.
     */

    public List<AbstractUserSummary> getSummaryBySearch(String searchQuery)
            throws SQLException {
        synchronized( this ) {
            if(searchQuery == null) {
                searchQuery = "%";
            } else if(searchQuery.indexOf('%') == -1) {
                searchQuery += "%";
            }

            return getMultiple(GET_SUMMARY_BY_SEARCH, searchQuery);
        }
    }

    //------------------------

    private static final class InstanceHolder {
        static final UserSummaryDAO INSTANCE = new UserSummaryDAO();
    }

    public static UserSummaryDAO getInstance() {
        return UserSummaryDAO.InstanceHolder.INSTANCE;
    }

}
