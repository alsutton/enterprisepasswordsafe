package com.enterprisepasswordsafe.ui.web.utils;

import com.enterprisepasswordsafe.database.ConfigurationDAO;
import com.enterprisepasswordsafe.database.ConfigurationOption;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.sql.SQLException;

public class BackButtonDetector {

    private final ConfigurationDAO configurationDAO;

    public BackButtonDetector() {
        configurationDAO = ConfigurationDAO.getInstance();
    }

    public void ensureBackIsNotUsedIfBlocked(final HttpServletRequest request)
            throws ServletException, SQLException {
        String backAllowed = configurationDAO.getValue(ConfigurationOption.ALLOW_BACK_BUTTON_TO_ACCESS_PASSWORD);
        if( backAllowed != null && backAllowed.equals("true") ) {
            return;
        }

        HttpSession session = request.getSession(false);
        String sessionOtid = (String) session.getAttribute("otid");
        if (sessionOtid == null || !sessionOtid.equals(getRequestOneTimeID(request))) {
            throw new ServletException("You can not view passwords using your browsers back button.");
        }
    }

    private String getRequestOneTimeID(HttpServletRequest request) {
        String requestOtid = request.getParameter("otid");
        return requestOtid == null ? (String) request.getAttribute("otid") : requestOtid;
    }
}
