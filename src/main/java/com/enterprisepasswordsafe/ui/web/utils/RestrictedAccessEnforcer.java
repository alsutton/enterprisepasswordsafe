package com.enterprisepasswordsafe.ui.web.utils;

import com.enterprisepasswordsafe.engine.database.*;
import com.enterprisepasswordsafe.engine.utils.DateFormatter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.sql.SQLException;

public class RestrictedAccessEnforcer {

    public static final String RA_REQUEST_ATTRIBUTE = "rar";

    private static final String RESTRICTED_ACCESS_PAGE = "/system/ra_reason.jsp";

    private static final String RESTRICTED_ACCESS_EXPIRED_PAGE = "/system/ra_expired.jsp";

    private static final String RESTRICTED_ACCESS_HOLDING_PAGE = "/system/ra_holding_page.jsp";

    public static final String RESTRICTED_ACCESS_LAST_REFRESH = "ra_last_refresh";

    public static final String REASON_PARAMETER = "reason";

    private static final String REASON_PAGE = "/system/view_password_reason.jsp";

    private ConfigurationDAO configurationDAO;
    private ServletUtils servletUtils;

    public RestrictedAccessEnforcer() {
        configurationDAO = ConfigurationDAO.getInstance();
        servletUtils = ServletUtils.getInstance();
    }

    public RestrictedAccessRequest ensureRestrictedAccessConditionsHaveBeenMet(HttpServletRequest request, User user,
                                                                               PasswordBase thisPassword)
            throws SQLException, RedirectException {
        if (!(thisPassword instanceof Password)) {
            return null;
        }

        Password password = (Password) thisPassword;
        if (!password.isRaEnabled()) {
            return null;
        }

        String raPage = getRaPage(password, user, request);
        if (raPage != null) {
            throw new RedirectException(raPage);
        }

        RestrictedAccessRequest raRequest = (RestrictedAccessRequest) request.getSession().getAttribute(RA_REQUEST_ATTRIBUTE);
        ServletUtils.getInstance().generateMessage(request,
                "This is a restricted access password. Your request to view it has been approved by the approproate users.");
        request.getSession().removeAttribute(RA_REQUEST_ATTRIBUTE);
        return raRequest;
    }

    private String getRaPage(final Password password, final User requester, final HttpServletRequest request)
            throws SQLException {
        HttpSession session = request.getSession();

        RestrictedAccessRequest raRequest = getRaREquestForPassword(password, requester, session);

        String divertPage = getDivertPageIfNeeded(request, password, raRequest);
        if (divertPage != null) {
            return divertPage;
        }

        if( raRequest.getViewedDT() < 0 ) {
            RestrictedAccessRequestDAO.getInstance().setViewedDT(raRequest, DateFormatter.getNow());
        }
        return null;
    }

    private RestrictedAccessRequest getRaREquestForPassword(Password password, User requester, HttpSession session)
            throws SQLException {
        RestrictedAccessRequest raRequest = (RestrictedAccessRequest) session.getAttribute(RA_REQUEST_ATTRIBUTE);
        if( raRequest != null
                && (!raRequest.getItemId().equals(password.getId()) || !raRequest.getRequesterId().equals(requester.getId()))) {
            session.removeAttribute(RA_REQUEST_ATTRIBUTE);
            raRequest = null;
        }

        if( raRequest == null ) {
            raRequest = RestrictedAccessRequestDAO.getInstance().getValidRequest(password.getId(), requester.getId());
            session.setAttribute(RA_REQUEST_ATTRIBUTE, raRequest);
        }

        return raRequest;
    }

    private String getDivertPageIfNeeded(HttpServletRequest request, Password password, RestrictedAccessRequest raRequest)
            throws SQLException {
        if( raRequest == null ) {
            request.setAttribute("id", password.getId());
            return RESTRICTED_ACCESS_PAGE;
        }
        if (raRequest.hasExpired() || hasRequestBeenBlocked(password, raRequest)) {
            request.getSession().removeAttribute(RA_REQUEST_ATTRIBUTE);
            return RESTRICTED_ACCESS_EXPIRED_PAGE;
        }

        int approvers = ApproverListDAO.getInstance().countApprovers(raRequest.getApproversListId());
        if (approvers < password.getRaApprovers()) {
            request.setAttribute(RESTRICTED_ACCESS_LAST_REFRESH, DateFormatter.convertToDateTimeString(DateFormatter.getNow()));
            request.setAttribute("rarId", raRequest.getRequestId());
            request.setAttribute("ra_refresh_url", "/system/ViewPassword?id=" + request.getParameter("id"));
            return RESTRICTED_ACCESS_HOLDING_PAGE;
        }

        return null;
    }

    private boolean hasRequestBeenBlocked(Password password, RestrictedAccessRequest raRequest)
            throws SQLException {
        int blockers = ApproverListDAO.getInstance().countBlockers(raRequest.getApproversListId());
        int blockersNeeded = password.getRaBlockers();
        return blockersNeeded != 0 && blockers >= blockersNeeded;
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
