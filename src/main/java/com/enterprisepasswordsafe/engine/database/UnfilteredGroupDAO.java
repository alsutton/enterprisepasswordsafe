package com.enterprisepasswordsafe.engine.database;

import com.enterprisepasswordsafe.proguard.ExternalInterface;

public class UnfilteredGroupDAO extends GroupStoreManipulator implements ExternalInterface {

    /**
     * The SQL to get a particular group by its' ID (includes disabled groups).
     */

    private static final String GET_BY_ID_SQL = "SELECT " + GROUP_FIELDS +
            "  FROM groups grp WHERE grp.group_id = ? AND grp.status < " + Group.STATUS_DELETED;

    private UnfilteredGroupDAO() {
        super(GET_BY_ID_SQL, null, null);
    }


    //------------------------

    private static final class InstanceHolder {
        static final UnfilteredGroupDAO INSTANCE = new UnfilteredGroupDAO();
    }

    public static UnfilteredGroupDAO getInstance() {
        return UnfilteredGroupDAO.InstanceHolder.INSTANCE;
    }

}
