package com.enterprisepasswordsafe.ui.web.servlets.utils;

import com.enterprisepasswordsafe.database.AccessControlDAO;
import com.enterprisepasswordsafe.database.User;
import com.enterprisepasswordsafe.engine.accesscontrol.AccessControl;

import javax.servlet.ServletException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;

public class AccessControlFetcher {

    public AccessControl getModifyAccessControl(User user, String passwordId) throws SQLException, ServletException,
            GeneralSecurityException, UnsupportedEncodingException {
        final AccessControl ac = AccessControlDAO.getInstance().getAccessControl(user, passwordId);
        if (ac == null) {
            throw new ServletException("You do not have access to this password.");
        }
        if (ac.getModifyKey() == null) {
            throw new ServletException("You do not have modification rights to the password.");
        }
        return ac;
    }
}
