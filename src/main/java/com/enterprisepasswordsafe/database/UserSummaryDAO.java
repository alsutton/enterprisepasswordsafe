package com.enterprisepasswordsafe.database;

import com.enterprisepasswordsafe.database.derived.UserSummary;
import com.enterprisepasswordsafe.engine.users.UserClassifier;
import com.enterprisepasswordsafe.engine.utils.Cache;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class UserSummaryDAO extends StoredObjectManipulator<UserSummary> {

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

    private final Cache<String, UserSummary> userSummaryCache = new Cache<>();

    public UserSummaryDAO() {
        super(GET_SUMMARY_BY_ID, GET_SUMMARY_BY_NAME, UserDAO.GET_COUNT_SQL);
    }

    @Override
    UserSummary newInstance(ResultSet rs, int startIndex) throws SQLException {
        return new UserSummary(
                rs.getString(startIndex),
                rs.getString(startIndex+1),
                rs.getString(startIndex + 2));
    }

    public List<UserSummary> getSummaryList()
            throws SQLException {
        return getMultiple(GET_SUMMARY_LIST_INCLUDING_ADMIN);
    }

    public List<UserSummary> getSummaryListExcludingAdmin()
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

    public List<UserSummary> getSummaryBySearch(String searchQuery)
            throws SQLException {
        synchronized( this ) {
            List<UserSummary> results= new ArrayList<>();

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
