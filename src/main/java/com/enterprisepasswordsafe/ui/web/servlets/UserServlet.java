/*
 * Copyright (c) 2017 Carbon Security Ltd. <opensource@carbonsecurity.co.uk>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package com.enterprisepasswordsafe.ui.web.servlets;

import com.enterprisepasswordsafe.database.*;
import com.enterprisepasswordsafe.database.derived.UserSummary;
import com.enterprisepasswordsafe.engine.users.UserClassifier;
import com.enterprisepasswordsafe.engine.users.UserPriviledgeTransitioner;
import com.enterprisepasswordsafe.engine.utils.StringUtils;
import com.enterprisepasswordsafe.ui.web.EPSUIException;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.Enumeration;
import java.util.Map;
import java.util.Objects;

public final class UserServlet extends HttpServlet {

    public static final String USER_TYPE_ADMIN = "A",
                                USER_TYPE_SUBADMIN = "P",
                                USER_TYPE_NORMAL = "N";

    private static final String GROUP_MEMBERSHIP_PERAMETER_PREFIX = "group_";

    private static final String ZONE_RULE_PREFIX = "zone_";

    private static final int ZONE_RULE_PREFIX_LENGTH = ZONE_RULE_PREFIX.length();

    private final UserClassifier userClassifier;

    public UserServlet() {
        this(new UserClassifier());
    }

    public UserServlet(UserClassifier userClassifier) {
        this.userClassifier = userClassifier;
    }

    @Override
    public void doGet(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
        String userId = request.getParameter("userId");
        if (userId == null) {
            Object userIdObject = request.getAttribute("userId");
            if(userIdObject != null) {
                userId = userIdObject.toString();
            }
        }

        try {
            addDataNeededForEditPage(request);

            User user = null;
            if (userId != null) {
                user = addUserInformation(request, userId);
            }

            if(user == null) {
                request.setAttribute("current_auth_source",
                        AuthenticationSourceDAO.getInstance().getById(AuthenticationSource.DEFAULT_SOURCE_ID));
            }

	        request.getRequestDispatcher("/admin/edit_user.jsp").forward(request, response);
        } catch(SQLException sqle) {
        	throw new ServletException("The user details are unavailable due to an error.", sqle);
        }
    }

    /**
     * @see javax.servlet.http.HttpServlet#doPost(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    @Override
    protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
            throws IOException, ServletException{
        String csrfToken = request.getParameter("token");
        if(csrfToken == null || !csrfToken.equals(request.getSession(true).getAttribute("csrfToken"))) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }

        try {
            User remoteUser = SecurityUtils.getRemoteUser(request);
            Group adminGroup = GroupDAO.getInstance().getAdminGroup(remoteUser);
            if(adminGroup == null) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN);
                return;
            }

            try {
                validatePasswordFields(request);
            } catch(EPSUIException e) {
                ServletUtils.getInstance().generateErrorMessage(request, e.getMessage());
                addDataNeededForEditPage(request);
                request.getRequestDispatcher("/admin/edit_user.jsp").forward(request, response);
                return;
            }

            UserDAO uDAO = UserDAO.getInstance();
            ServletUtils servletUtils = ServletUtils.getInstance();

            String userId = request.getParameter("userId");
            boolean newUser = uDAO.getById(userId) == null;
            User user = getUser(request, remoteUser, adminGroup, userId);

            setUserPriviledgeLevel(request, remoteUser, adminGroup, user);
            String enabled = request.getParameter("user_enabled");
            if (enabled.equals("Y")) {
                if( ! user.isEnabled() ) {
                    uDAO.setFailedLogins(user, 0);
                }
                user.setEnabled(true);
            } else {
                user.setEnabled(false);
            }

            String forcePwdChange = request.getParameter("force_change_password");
            if( forcePwdChange != null && forcePwdChange.equals("Y") ) {
                user.forcePasswordChangeAtNextLogin();
            }

            uDAO.update(user);

            updateGroupMemberships(request, remoteUser, user);
            updateRestrictions(request, user);

            servletUtils.generateMessage(request, newUser ? "The profile has been created." :
                    "The profile has been updated.");
            response.sendRedirect(request.getContextPath()+"/admin/User?userId="+user.getId());
        } catch(Exception e) {
            throw new ServletException("There was a problem updating the user.", e);
        }
    }

    private User getUser(HttpServletRequest request, User remoteUser, Group adminGroup, String userId)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        ServletUtils servletUtils = ServletUtils.getInstance();
        UserDAO uDAO = UserDAO.getInstance();
        User user = null;
        if(userId != null && !userId.isEmpty()) {
            user = uDAO.getById(userId);
        }
        if(user == null) {
            return uDAO.createUser( remoteUser,
                    new UserSummary(servletUtils.getParameterValue(request, "username"),
                            servletUtils.getParameterValue(request, BaseServlet.FULL_NAME_PARAMETER)),
                    servletUtils.getParameterValue(request, "password1"),
                    servletUtils.getParameterValue(request, BaseServlet.EMAIL_PARAMETER));
        }

        user.decryptAdminAccessKey(adminGroup);

        user.setFullName(servletUtils.getParameterValue(request, BaseServlet.FULL_NAME_PARAMETER));
        user.setEmail(servletUtils.getParameterValue(request, BaseServlet.EMAIL_PARAMETER));
        user.setAuthSource(servletUtils.getParameterValue(request, BaseServlet.AUTH_SOURCE_ATTRIBUTE));

        String newPassword = request.getParameter("password1");
        if(newPassword != null && !newPassword.isEmpty()) {
            user.decryptAdminAccessKey(adminGroup);
            uDAO.updatePassword(user, newPassword);
        }
        return user;
    }

    /**
     * Add the information to the HttpServletRequest which is needed to display the
     * user editing page.
     *
     * @param request The request being serviced.
     */

    private void addDataNeededForEditPage(final HttpServletRequest request)
        throws SQLException {
        request.setAttribute("auth_sources", AuthenticationSourceDAO.getInstance().getAll());
        request.setAttribute("groups", GroupDAO.getInstance().getNonSystem());
        request.setAttribute("restrictions", IPZoneDAO.getInstance().getAll());
    }

    /**
     * Add details about a specific user to the HttpServletRequest.
     *
     * @param request The request being serviced.
     * @param id The ID of the user whose details should be added to the response.
     */

    private User addUserInformation(final HttpServletRequest request, final String id)
        throws SQLException {
        User user = UserDAO.getInstance().getById(id);
        if(user == null) {
            return null;
        }

        Map<String, Object> memberships = MembershipDAO.getInstance().getMemberships(id);
        request.setAttribute("group_membership_map", memberships);
        request.setAttribute("restrictions_map", UserIPZoneRestrictionDAO.getInstance().getRulesForUser(id));
        request.setAttribute("user_level", userClassifier.getUserLevelFrom(memberships));
        request.setAttribute("non_viewing", userClassifier.isNonViewingUser(user));

        String authSourceId = (user.getAuthSource() == null) ? AuthenticationSource.DEFAULT_SOURCE_ID : user.getAuthSource();
        request.setAttribute("current_auth_source", AuthenticationSourceDAO.getInstance().getById(authSourceId));

        request.setAttribute("user", user);

        return user;
    }

    /**
     * Validate the values supplied in the password fields.
     *
     * @param request The request being serviced.
     */

    private void validatePasswordFields(final HttpServletRequest request)
        throws EPSUIException, SQLException {
        String password1 = request.getParameter("password1");
        String password2 = request.getParameter("password2");
        if ((password1 == null || password1.isEmpty())
        &&  (password2 == null || password2.isEmpty())) {
            return;
        }

        if ( StringUtils.isAnyEmpty(password1, password2) || !Objects.equals(password1, password2)) {
            throw new EPSUIException("The passwords you entered were not the same.");
        }

        PasswordRestriction control = PasswordRestrictionDAO.getInstance().getById(
                PasswordRestriction.LOGIN_PASSWORD_RESTRICTION_ID);
        if (control != null && !control.verify(password1)) {
            throw new EPSUIException(
                    "The users password has NOT been updated because it does not meet the following requirements; "
                            +control.toString());
        }

    }

    private void updateGroupMemberships(final HttpServletRequest request, final User remoteUser, final User user)
        throws SQLException, GeneralSecurityException, UnsupportedEncodingException {

        MembershipDAO mDAO = MembershipDAO.getInstance();
        for(Group group : GroupDAO.getInstance().getAll() ) {
            String groupId = group.getGroupId();
            String flag = request.getParameter(GROUP_MEMBERSHIP_PERAMETER_PREFIX+groupId);
            boolean membershipRequested = (flag != null && !flag.isEmpty());

            if(membershipRequested) {
                mDAO.create(remoteUser, user, groupId);
            } else {
                mDAO.delete(user, groupId);
            }
        }
    }

    private void updateRestrictions(final HttpServletRequest request, final User user)
        throws SQLException {
        String userId = user.getId();
        Enumeration<String> parameterNames = request.getParameterNames();
        while(parameterNames.hasMoreElements()) {
            String parameterName = parameterNames.nextElement();
            processParameter(request, userId, parameterName);
        }
    }

    private void processParameter(HttpServletRequest request, String userId, String parameterName) throws SQLException {
        if(!parameterName.startsWith(ZONE_RULE_PREFIX)) {
            return;
        }
        String zoneId = parameterName.substring(ZONE_RULE_PREFIX_LENGTH);
        String rule = request.getParameter(parameterName);

        UserIPZoneRestrictionDAO uipzrDAO = UserIPZoneRestrictionDAO.getInstance();
        UserIPZoneRestriction restriction = uipzrDAO.getByZoneAndUser(userId, zoneId);
        if( rule.equals(UserIPZoneRestriction.DEFAULT_STRING) ) {
            setAsDefault(uipzrDAO, restriction);
        } else {
            setRule(uipzrDAO, restriction, zoneId, userId, rule);
        }
    }

    private void setAsDefault(UserIPZoneRestrictionDAO uipzrDAO, UserIPZoneRestriction restriction)
            throws SQLException {
        if( restriction != null ) {
            uipzrDAO.delete(restriction);
        }
    }

    private void setRule(UserIPZoneRestrictionDAO uipzrDAO, UserIPZoneRestriction restriction,
                         String zoneId, String userId, String rule)
            throws SQLException {
        int ruleValue = UserIPZoneRestriction.DENY_INT;
        if( rule.equals(UserIPZoneRestriction.ALLOW_STRING) ) {
            ruleValue = UserIPZoneRestriction.ALLOW_INT;
        }

        if( restriction == null ) {
            uipzrDAO.create(zoneId, userId, ruleValue);
        } else {
            restriction.setRule(ruleValue);
            uipzrDAO.update(restriction);
        }
    }

    private void setUserPriviledgeLevel(final HttpServletRequest request, final User remoteUser,
                                        final Group adminGroup, final User user)
            throws GeneralSecurityException, SQLException, IOException {
        UserPriviledgeTransitioner userPriviledgeTransitioner = new UserPriviledgeTransitioner();
        switch(request.getParameter("user_type")) {
            case USER_TYPE_ADMIN:
                userPriviledgeTransitioner.makeAdmin(remoteUser, adminGroup, user);
                break;
            case USER_TYPE_SUBADMIN:
                userPriviledgeTransitioner.makeSubadmin(remoteUser, adminGroup, user);
                break;
            case USER_TYPE_NORMAL:
                userPriviledgeTransitioner.makeNormalUser(remoteUser, user);
                break;
        }

        String noView = request.getParameter("noview");
        userPriviledgeTransitioner.setNotViewing(user, noView != null && noView.equals("Y"));
    }

    @Override
	public String getServletInfo() {
        return "Obtains the information about a user to be edited.";
    }
}
