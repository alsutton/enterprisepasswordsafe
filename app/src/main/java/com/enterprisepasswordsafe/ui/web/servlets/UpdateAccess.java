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
import com.enterprisepasswordsafe.engine.users.UserClassifier;
import com.enterprisepasswordsafe.model.dao.*;
import com.enterprisepasswordsafe.model.persisted.LogEntry;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletPaths;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * Servlet to alter a users access to a password.
 */

public final class UpdateAccess extends HttpServlet {

	/**
     * The prefix for a user parameter.
     */

    private static final String USER_PARAMETER_PREFIX = "u_";

    /**
     * The size of the user parameter prefix
     */

    private static final int USER_PARAMETER_PREFIX_LENGTH = USER_PARAMETER_PREFIX.length();

    /**
     * The prefix for a user parameter.
     */

    private static final String GROUP_PARAMETER_PREFIX = "g_";

    /**
     * The size of the user parameter prefix
     */

    private static final int GROUP_PARAMETER_PREFIX_LENGTH = GROUP_PARAMETER_PREFIX.length();

    /**
     * The page users are directed to if there is an error.
     */

    private static final String ERROR_PAGE = ServletPaths.getExplorerPath();

    /**
     * @see javax.servlet.http.HttpServlet#doPost(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    @Override
	protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException {
    	try {
	    	User currentUser = SecurityUtils.getRemoteUser(request);
	        ServletUtils servletUtils = ServletUtils.getInstance();
	        if (!new UserClassifier().isPriviledgedUser(currentUser)) {
	        	servletUtils.generateErrorMessage(request, "You can not modify access to this password");
                response.sendRedirect(request.getContextPath() + ERROR_PAGE);
	        	return;
	        }

	        String passwordId = servletUtils.getParameterValue(request, SharedParameterNames.PASSWORD_ID_PARAMETER);

	        // Verify the access control is in place
	        Group adminGroup = GroupDAO.getInstance().getAdminGroup(currentUser);
	        AccessControl ac = GroupPasswordAccessControlDAO.getInstance().get(adminGroup, passwordId);
	        if( ac == null || ac.getReadKey() == null || ac.getModifyKey() == null ) {
	        	servletUtils.generateErrorMessage(request, "You can not modify access to the specified password");
                response.sendRedirect(request.getContextPath() + ERROR_PAGE);
	        	return;
	        }

	        Password password = UnfilteredPasswordDAO.getInstance().getById(passwordId, ac);
	        User adminUser = UserDAO.getInstance().getAdminUser(adminGroup);

	        RoleChangeContext context = new RoleChangeContext(currentUser, adminUser, adminGroup, password);
	        processRoleChanges(request, context, ac);

	    	servletUtils.generateMessage(request, "The password access rights were updated.");
	    	response.sendRedirect(request.getContextPath()+"/subadmin/AlterAccess?id="+password.getId());
    	} catch(Exception ex) {
    		throw new ServletException("The access rules could not be updated due to an error.", ex);
    	}
    }

    private void processRoleChanges(HttpServletRequest request, RoleChangeContext context, AccessControl ac)
            throws GeneralSecurityException, UnsupportedEncodingException, SQLException {
        Enumeration<String> params = request.getParameterNames();
        while( params.hasMoreElements() ) {
            String thisParameter = params.nextElement();

            String value = request.getParameter(thisParameter);

            if			( thisParameter.startsWith(USER_PARAMETER_PREFIX) ) {
                handleUserParameter(context, ac, thisParameter, value);
            } else if	( thisParameter.startsWith(GROUP_PARAMETER_PREFIX) ) {
                handleGroupParameter(context, ac, thisParameter, value);
            }
        }

		processUserRoles(request, context, AccessRolesPresentation.USER_HISTORY);
        processGroupRoles(request, context, AccessRolesPresentation.GROUP_HISTORY);
        processUserRoles(request, context, AccessRolesPresentation.USER_RA_APPROVER);
        processGroupRoles(request, context, AccessRolesPresentation.GROUP_RA_APPROVER);
    }

    private void handleUserParameter(final RoleChangeContext context, final AccessControl ac,
    		final String thisParameter, final String value )
    	throws UnsupportedEncodingException, SQLException, GeneralSecurityException
    {
		int endOfId = thisParameter.indexOf('_', USER_PARAMETER_PREFIX_LENGTH);
		String userId = thisParameter.substring(USER_PARAMETER_PREFIX_LENGTH, endOfId);
		char parameterType = thisParameter.charAt(endOfId+1);
		String originalValue = thisParameter.substring(endOfId+2);
		if( value.equals(originalValue) ) {
			return;
		}

		User theUser = UserDAO.getInstance().getByIdDecrypted(userId, context.adminGroup);
		if			( parameterType == 'a' ) {
			changeAccess(context, ac, theUser, value);
		}
    }

    private void handleGroupParameter(final RoleChangeContext context, final AccessControl ac,
                                      final String thisParameter, final String value )
    	throws UnsupportedEncodingException, SQLException, GeneralSecurityException
    {
		int endOfId = thisParameter.indexOf('_', GROUP_PARAMETER_PREFIX_LENGTH);
		String groupId = thisParameter.substring(GROUP_PARAMETER_PREFIX_LENGTH, endOfId);

		String originalValue = thisParameter.substring(endOfId+2);
		if( value.equals(originalValue) ) {
			return;
		}

		Group theGroup = UnfilteredGroupDAO.getInstance().getById(groupId);
		if (theGroup == null) {
			throw new RuntimeException("One of the specified groups does not exist anymore.");
		}
    	Membership membership = MembershipDAO.getInstance().getMembership(context.adminUser, theGroup);
    	if (membership == null) {
    		throw new GeneralSecurityException("You are not allow to alter the rights on the group "+theGroup.getGroupName()+".");
    	}
    	theGroup.updateAccessKey(membership);

		char parameterType = thisParameter.charAt(endOfId+1);

		if			( parameterType == 'a' ) {
			changeAccess(context, ac, theGroup, value);
		}
    }

    private void processUserRoles(final HttpServletRequest request, final RoleChangeContext context,
                                  final AccessRolesPresentation accessRolesPresentation)
    throws UnsupportedEncodingException, SQLException, GeneralSecurityException {
        List<String> onNow = new ArrayList<>();
        List<String> previouslyOn = new ArrayList<>();
		determineOldAndNewStates(request, accessRolesPresentation, previouslyOn, onNow);

		UserAccessRoleDAO uarDEO = UserAccessRoleDAO.getInstance();
		String remoteUserId = context.currentUser.getId();
    	for(String id : onNow) {
    		if(previouslyOn.contains(id)) {
    			previouslyOn.remove(id);
    			continue;
    		}
            uarDEO.create(context.password.getId(), remoteUserId, accessRolesPresentation.internalRoleIdentifier );
            logAndEmailIfNeeded(context.password, context.currentUser,
            "Gave the user {user:"+remoteUserId+"} the right to "+accessRolesPresentation.description);
    	}

    	for(String id: previouslyOn) {
            logAndEmailIfNeeded(context.password, context.currentUser,
                    "Removed the right to "+accessRolesPresentation.description+" from the user {user:"+id+"}" );
            UserAccessRoleDAO.getInstance().delete( context.password.getId(), id,
                    accessRolesPresentation.internalRoleIdentifier );
    	}
    }

    private void processGroupRoles(final HttpServletRequest request, final RoleChangeContext context,
                                   final AccessRolesPresentation accessRolesPresentation)
    throws UnsupportedEncodingException, SQLException, GeneralSecurityException {
        List<String> onNow = new ArrayList<>();
        List<String> previouslyOn = new ArrayList<>();
        determineOldAndNewStates(request, accessRolesPresentation, previouslyOn, onNow);

    	for(String id : onNow) {
    		if(previouslyOn.contains(id)) {
    			previouslyOn.remove(id);
    			continue;
    		}
            logAndEmailIfNeeded(context.password, context.currentUser,
                    "Gave the group {group:"+id+"} the right to "+accessRolesPresentation.description);
            GroupAccessRoleDAO.getInstance().create( context.password.getId(), id,
                    accessRolesPresentation.internalRoleIdentifier );
    	}

    	for(String id: previouslyOn) {
            logAndEmailIfNeeded(context.password, context.currentUser,
                    "Removed the right to "+accessRolesPresentation.description+" from the group {group:"+id+"}");
            GroupAccessRoleDAO.getInstance().delete(context.password.getId(), id,
                    accessRolesPresentation.internalRoleIdentifier);
    	}
    }

    private void determineOldAndNewStates(	HttpServletRequest request, AccessRolesPresentation accessRolesPresentation,
                                              List<String> previous, List<String> now) {
		Enumeration<String> params = request.getParameterNames();
		while( params.hasMoreElements() ) {
			String thisParameter = params.nextElement();

			if	( thisParameter.startsWith(accessRolesPresentation.uiPrefixForOld)) {
				previous.add(thisParameter.substring(4));
			} else if	( thisParameter.startsWith(accessRolesPresentation.uiPrefixForNew)) {
				now.add(thisParameter.substring(3));
			}
		}
	}

    private void changeAccess(RoleChangeContext context, final AccessControl adminAc, final User theUser,
                              final String access )
    	throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
		// Get the existing UAC (if it exists);
		UserPasswordAccessControlDAO uacDAO = UserPasswordAccessControlDAO.getInstance();
		UserAccessControl currentUac = uacDAO.get(theUser, context.password);
		if (access.equals("N")) {
			if (currentUac != null) {
				uacDAO.delete(currentUac);
				logAndEmailIfNeeded(context.password, context.adminUser, "Removed all permissions for " + theUser.getUserName());
			}
		} else if(needsUpdate(adminAc, currentUac, uacDAO, theUser, context.password, access, UserAccessControl.builder())) {
			logAndEmailIfNeeded(context.password, context.adminUser, "Changed the access permissions on the user {user:"
					+ theUser.getId() + "} to be " + access);
		}
    }

    private void changeAccess(final RoleChangeContext context, final AccessControl adminAc, final Group theGroup,
                              final String access )
    	throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
    	GroupPasswordAccessControlDAO gacDAO = GroupPasswordAccessControlDAO.getInstance();
    	GroupAccessControl currentGac = gacDAO.get( context.adminUser, theGroup, context.password );
	    if (access.equals("N")) {
	    	if( currentGac != null ) {
	    		gacDAO.delete(currentGac);
				logAndEmailIfNeeded(context.password, context.adminUser, "Removed all permissions for the group {group:" +
						theGroup.getGroupId()+"}");
	    	}
	    } else if (needsUpdate(adminAc, currentGac, gacDAO, theGroup, context.password, access, GroupAccessControl.builder())) {
	    	logAndEmailIfNeeded(context.password, context.adminUser, "Changed the access permissions on the group {group:"
					+ theGroup.getGroupId() + "} to be " + access);
		}
    }

    private void logAndEmailIfNeeded(Password thePassword, User adminUser, String message)
			throws GeneralSecurityException, UnsupportedEncodingException, SQLException {
		LoggingDAO.getInstance().create( LogEntry.LOG_LEVEL_OBJECT_MANIPULATION,
				adminUser, thePassword, message, thePassword.getAuditLevel().shouldTriggerEmail());
	}

    private boolean needsUpdate(AccessControl adminAc, AccessControl currentAccessControl,
								GroupPasswordAccessControlDAO accessControlDAO,
								Group entity, Password thePassword, String access,
								AccessControlBuilder<GroupAccessControl> accessControlBuilder)
			throws GeneralSecurityException, SQLException {
        PasswordPermission permission = PasswordPermission.fromRepresentation(access);
		if( currentAccessControl == null ) {
			accessControlDAO.create(entity, thePassword, permission);
			return true;
		} else {
            accessControlBuilder = accessControlBuilder.copyFrom(currentAccessControl);
			if(updateAccessControl(adminAc, currentAccessControl, permission, accessControlBuilder)) {
				accessControlDAO.update(entity, accessControlBuilder.build());
				return true;
			}
		}
		return false;
	}

	private boolean needsUpdate(AccessControl adminAc, AccessControl currentAccessControl,
								UserPasswordAccessControlDAO accessControlDAO,
								User entity, Password thePassword, String access,
								AccessControlBuilder<UserAccessControl> accessControlBuilder)
			throws GeneralSecurityException, UnsupportedEncodingException, SQLException {
		PasswordPermission permission = PasswordPermission.fromRepresentation(access);
		if( currentAccessControl == null ) {
			accessControlDAO.create(entity, thePassword, permission);
			return true;
		} else {
			accessControlBuilder = accessControlBuilder.copyFrom(currentAccessControl);
			if(updateAccessControl(adminAc, currentAccessControl, permission, accessControlBuilder)) {
				accessControlDAO.update(entity, accessControlBuilder.build());
				return true;
			}
		}
		return false;
	}

	private boolean updateAccessControl(AccessControl adminAc, AccessControl currentAccessControl,
										PasswordPermission permission,
										AccessControlBuilder<? extends AccessControl> accessControlBuilder) {
		boolean changed = false;
		if( permission.allowsRead && currentAccessControl.getReadKey() == null ) {
			accessControlBuilder.withReadKey(adminAc.getReadKey());
			changed = true;
		}
		if( permission.allowsModification && currentAccessControl.getModifyKey() == null ) {
			accessControlBuilder.withModifyKey(adminAc.getModifyKey());
			changed = true;
		}
		if( !permission.allowsModification && currentAccessControl.getModifyKey() != null ) {
			accessControlBuilder.withModifyKey(null);
			changed = true;
		}
		return changed;
	}

    @Override
	public String getServletInfo() {
        return "Updates the access a user has to a password";
    }

    private static class RoleChangeContext {
        final User currentUser;
        final User adminUser;
        final Group adminGroup;
        final Password password;

        private RoleChangeContext(User currentUser, User adminUser, Group adminGroup, Password password) {
            this.currentUser = currentUser;
            this.adminUser = adminUser;
            this.adminGroup = adminGroup;
            this.password = password;
        }
    }
}
