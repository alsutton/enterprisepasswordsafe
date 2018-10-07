package com.enterprisepasswordsafe.ui.web.utils;

import com.enterprisepasswordsafe.engine.database.ConfigurationDAO;
import com.enterprisepasswordsafe.engine.database.ConfigurationOption;
import com.enterprisepasswordsafe.engine.database.PasswordBase;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.sql.SQLException;

public class RestrictedAccessEnforcer {

    public static final String REASON_PARAMETER = "reason";

    private static final String REASON_PAGE = "/system/view_password_reason.jsp";

    private ConfigurationDAO configurationDAO;
    private ServletUtils servletUtils;

    public RestrictedAccessEnforcer() {
        configurationDAO = ConfigurationDAO.getInstance();
        servletUtils = ServletUtils.getInstance();
    }

    public boolean ensureReasonSuppliedIfRequired(HttpServletRequest request, PasswordBase thisPassword)
            throws SQLException, RedirectException {
        String reasonRequired = configurationDAO.get(ConfigurationOption.PASSWORD_REASON_FOR_VIEWING_REQUIRED);
        if( reasonRequired.charAt(0) != 'y') {
            clearReasonSessionAttributes(request);
            request.setAttribute("reason", "");
            return true;
        }

        boolean logRequired = true;
        String reason = request.getParameter(REASON_PARAMETER);
        if( reason == null || reason.trim().length() == 0 ) {
            String lastReasonViewId = (String) request.getSession().getAttribute("reason.lastid");
            String lastPassword = (String) request.getSession().getAttribute("reason.password");
            if( lastReasonViewId != null &&	lastReasonViewId.equals(thisPassword.getId())
                    &&	lastPassword != null &&	lastPassword.equals(thisPassword.getPassword())) {
                reason = (String) request.getSession().getAttribute("reason.text");
                logRequired = false;
            }
        }

        clearReasonSessionAttributes(request);
        ensureReasonHasBeenSupplied(request, thisPassword, reason);

        request.getSession().setAttribute("reason.lastid", thisPassword.getId());
        request.getSession().setAttribute("reason.password", thisPassword.getPassword());
        request.getSession().setAttribute("reason.text", reason);
        request.setAttribute("reason", reason);

        return logRequired;
    }


    private void ensureReasonHasBeenSupplied(HttpServletRequest request, PasswordBase password, String reason)
            throws RedirectException {
        if( reason != null && !reason.isEmpty()) {
            return;
        }

        String displayValue = request.getParameter("display");
        if( displayValue == null ) {
            displayValue = "";
        }
        request.setAttribute("display", displayValue);
        request.setAttribute("id", password.getId());
        servletUtils.generateErrorMessage(request, "You must enter a reason for viewing the password.");
        throw new RedirectException(REASON_PAGE);
    }

    private void clearReasonSessionAttributes(HttpServletRequest request) {
        HttpSession session = request.getSession();
        session.removeAttribute("reason.lastid");
        session.removeAttribute("reason.password");
        session.removeAttribute("reason.text");
    }
}
