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

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.enterprisepasswordsafe.engine.database.*;
import com.enterprisepasswordsafe.engine.database.schema.AccessControlDAOInterface;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletPaths;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

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
	        if (!currentUser.isAdministrator() &&  !currentUser.isSubadministrator()) {
	        	servletUtils.generateErrorMessage(request, "You can not modify access to this password");
                response.sendRedirect(request.getContextPath() + ERROR_PAGE);
	        	return;
	        }

	        String passwordId = servletUtils.getParameterValue(request, SharedParameterNames.PASSWORD_ID_PARAMETER);

	        // Verify the access control is in place
	        Group adminGroup = GroupDAO.getInstance().getAdminGroup(currentUser);
	        AccessControl ac = GroupAccessControlDAO.getInstance().getGac(adminGroup, passwordId);
	        if( ac == null || ac.getReadKey() == null || ac.getModifyKey() == null ) {
	        	servletUtils.generateErrorMessage(request, "You can not modify access to the specified password");
                response.sendRedirect(request.getContextPath() + ERROR_PAGE);
	        	return;
	        }

	        Password password = PasswordDAO.getInstance().getByIdEvenIfDisabled(ac, passwordId);
	        User adminUser = UserDAO.getInstance().getAdminUser(adminGroup);

	        processRoleChanges(request, password, adminUser, adminGroup, currentUser, ac);

	    	servletUtils.generateMessage(request, "The password access rights were updated.");
	    	response.sendRedirect(request.getContextPath()+"/subadmin/AlterAccess?id="+password.getId());
    	} catch(Exception ex) {
    		throw new ServletException("The access rules could not be updated due to an error.", ex);
    	}
    }

    private void processRoleChanges(HttpServletRequest request, Password password, User adminUser,
                                    Group adminGroup, User currentUser, AccessControl ac)
            throws GeneralSecurityException, UnsupportedEncodingException, SQLException {
        Enumeration<String> params = request.getParameterNames();
        while( params.hasMoreElements() ) {
            String thisParameter = params.nextElement();

            String value = request.getParameter(thisParameter);

            if			( thisParameter.startsWith(USER_PARAMETER_PREFIX) ) {
                handleUserParameter(adminGroup, currentUser, password, ac, thisParameter, value);
            } else if	( thisParameter.startsWith(GROUP_PARAMETER_PREFIX) ) {
                handleGroupParameter(adminUser, currentUser, password, ac, thisParameter, value);
            }
        }

        processUserHistoryRoles(currentUser, password, request);
        processUserRARoles(currentUser, password, request);
        processGroupHistoryRoles(currentUser, password, request);
        processGroupRARoles(currentUser, password, request);
    }

    private void handleUserParameter(final Group adminGroup, final User adminUser,
    		final Password password, final AccessControl ac,
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

		User theUser = UserDAO.getInstance().getByIdDecrypted(userId, adminGroup);
		if			( parameterType == 'a' ) {
			changeAccess(adminUser, ac, password, theUser, value);
		}
    }

    private void handleGroupParameter(final User theAdmin,
    		final User adminUser, final Password password,
		    final AccessControl ac, final String thisParameter,
		  	final String value )
    	throws UnsupportedEncodingException, SQLException, GeneralSecurityException
    {
		int endOfId = thisParameter.indexOf('_', GROUP_PARAMETER_PREFIX_LENGTH);
		String groupId = thisParameter.substring(GROUP_PARAMETER_PREFIX_LENGTH, endOfId);

		String originalValue = thisParameter.substring(endOfId+2);
		if( value.equals(originalValue) ) {
			return;
		}

		Group theGroup = GroupDAO.getInstance().getByIdEvenIfDisabled(groupId);
		if (theGroup == null) {
			throw new RuntimeException("One of the specified groups does not exist anymore.");
		}
    	Membership membership = MembershipDAO.getInstance().getMembership(theAdmin, theGroup);
    	if (membership == null) {
    		throw new GeneralSecurityException("You are not allow to alter the rights on the group "+theGroup.getGroupName()+".");
    	}
    	theGroup.updateAccessKey(membership);

		char parameterType = thisParameter.charAt(endOfId+1);

		if			( parameterType == 'a' ) {
			changeAccess(adminUser, ac, password, theGroup, value);
		}
    }

    private void processUserRARoles(final User remoteUser, final Password password, final HttpServletRequest request)
    throws UnsupportedEncodingException, SQLException, GeneralSecurityException {
    	processUserRoles(remoteUser, password, request, "our_", "ur_",
        		"approved restricted access requests", AccessRole.APPROVER_ROLE);
    }

    private void processGroupRARoles(final User remoteUser, final Password password, final HttpServletRequest request)
    throws UnsupportedEncodingException, SQLException, GeneralSecurityException {
    	processGroupRoles(remoteUser, password, request, "ogr_", "gr_",
        		"approved restricted access requests", AccessRole.APPROVER_ROLE);
    }


    private void processUserHistoryRoles(final User remoteUser, final Password password, final HttpServletRequest request)
    throws UnsupportedEncodingException, SQLException, GeneralSecurityException {
    	processUserRoles(remoteUser, password, request, "ouh_", "uh_",
        		"view the password history", AccessRole.HISTORYVIEWER_ROLE);
    }

    private void processGroupHistoryRoles(final User remoteUser, final Password password, final HttpServletRequest request)
    throws UnsupportedEncodingException, SQLException, GeneralSecurityException {
    	processGroupRoles(remoteUser, password, request, "ogh_", "gh_",
        		"view the password history", AccessRole.HISTORYVIEWER_ROLE);
    }

    private void processUserRoles(final User remoteUser, final Password password, final HttpServletRequest request,
                                  final String originalPrefix, final String setPrefix, final String roleDescription,
                                  final String role)
    throws UnsupportedEncodingException, SQLException, GeneralSecurityException {
        List<String> onNow = new ArrayList<>();
        List<String> previouslyOn = new ArrayList<>();
		determineOldAndNewStates(request, originalPrefix, previouslyOn, setPrefix, onNow);

    	for(String id : onNow) {
    		if(previouslyOn.contains(id)) {
    			previouslyOn.remove(id);
    			continue;
    		}
    		giveUserRole(remoteUser, password, id, roleDescription, role);
    	}

    	for(String id: previouslyOn) {
    		removeUserRole(remoteUser, password, id, roleDescription, role);
    	}
    }

    private void processGroupRoles(final User remoteUser, final Password password,
    		final HttpServletRequest request, final String originalPrefix, final String setPrefix,
			final String roleDescription, final String role)
    throws UnsupportedEncodingException, SQLException, GeneralSecurityException {
        List<String> onNow = new ArrayList<>();
        List<String> previouslyOn = new ArrayList<>();
		determineOldAndNewStates(request, originalPrefix, previouslyOn, setPrefix, onNow);

    	for(String id : onNow) {
    		if(previouslyOn.contains(id)) {
    			previouslyOn.remove(id);
    			continue;
    		}
    		giveGroupRole(remoteUser, password, id, roleDescription, role);
    	}

    	for(String id: previouslyOn) {
    		removeGroupRole(remoteUser, password, id, roleDescription,role);
    	}
    }

    private void determineOldAndNewStates(	HttpServletRequest request, String previousPrefix, List<String> previous,
									 		String nowPrefix, List<String> now) {
		Enumeration<String> params = request.getParameterNames();
		while( params.hasMoreElements() ) {
			String thisParameter = params.nextElement();

			if	( thisParameter.startsWith(previousPrefix)) {
				previous.add(thisParameter.substring(4));
			} else if	( thisParameter.startsWith(nowPrefix)) {
				now.add(thisParameter.substring(3));
			}
		}
	}

    private void giveUserRole(final User remoteUser, final Password password, final String userId,
    		final String roleName, final String role)
    throws UnsupportedEncodingException, SQLException, GeneralSecurityException {
		UserAccessRoleDAO.getInstance().create( password.getId(), userId, role );
		logAndEmailIfNeeded(password, remoteUser, "Gave the user {user:"+userId+"} the right to "+roleName);
    }

    private void removeUserRole(final User remoteUser, final Password password, final String userId,
    		final String roleName, final String role)
    throws UnsupportedEncodingException, SQLException, GeneralSecurityException {
        logAndEmailIfNeeded(password, remoteUser,
                "Removed the right to "+roleName+" from the user {user:"+userId+"}" );
		UserAccessRoleDAO.getInstance().delete( password.getId(), userId, role );
    }

    private void giveGroupRole(final User remoteUser, final Password password, final String groupId,
    		final String roleName, final String role )
    throws UnsupportedEncodingException, SQLException, GeneralSecurityException {
        logAndEmailIfNeeded(password, remoteUser, "Gave the group {group:"+groupId+"} the right to "+roleName);
		GroupAccessRoleDAO.getInstance().create( password.getId(), groupId, role );
    }

    private void removeGroupRole(final User remoteUser, final Password password, final String groupId,
                                 final String roleName, final String role)
    throws UnsupportedEncodingException, SQLException, GeneralSecurityException {
        logAndEmailIfNeeded(password, remoteUser,
                "Removed the right to "+roleName+" from the group {group:"+groupId+"}");
		GroupAccessRoleDAO.getInstance().delete(password.getId(), groupId, role);
    }

    private void changeAccess(final User adminUser, final AccessControl adminAc, final Password thePassword,
    		final User theUser, final String access )
    	throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
		// Get the existing UAC (if it exists);
		UserAccessControlDAO uacDAO = UserAccessControlDAO.getInstance();
		UserAccessControl currentUac = uacDAO.getUac(theUser, thePassword);
		if (access.equals("N")) {
			if (currentUac != null) {
				uacDAO.delete(currentUac);
				logAndEmailIfNeeded(thePassword, adminUser, "Removed all permissions for " + theUser.getUserName());
			}
		} else if(modifyOrCreateAccessControl(adminAc, currentUac, uacDAO, theUser, thePassword, access)) {
			logAndEmailIfNeeded(thePassword, adminUser, "Changed the access permissions on the user {user:"
					+ theUser.getUserId() + "} to be " + access);
		}
    }

    private void changeAccess(final User adminUser, final AccessControl adminAc, final Password thePassword,
    		final Group theGroup, final String access )
    	throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
    	GroupAccessControlDAO gacDAO = GroupAccessControlDAO.getInstance();
    	GroupAccessControl currentGac = gacDAO.getGac( adminUser, theGroup, thePassword );
	    if (access.equals("N")) {
	    	if( currentGac != null ) {
	    		gacDAO.delete(currentGac);
				logAndEmailIfNeeded(thePassword, adminUser, "Removed all permissions for the group {group:" +
						theGroup.getGroupId()+"}");
	    	}
	    } else if (modifyOrCreateAccessControl(adminAc, currentGac, gacDAO, theGroup, thePassword, access)) {
	    	logAndEmailIfNeeded(thePassword, adminUser, "Changed the access permissions on the group {group:"
					+ theGroup.getGroupId() + "} to be " + access);
		}
    }

    private void logAndEmailIfNeeded(Password thePassword, User adminUser, String message)
			throws GeneralSecurityException, UnsupportedEncodingException, SQLException {
		TamperproofEventLogDAO.getInstance().create( TamperproofEventLog.LOG_LEVEL_OBJECT_MANIPULATION,
				adminUser, thePassword, message, ((thePassword.getAuditLevel() & Password.AUDITING_EMAIL_ONLY)!=0));
	}

    private boolean modifyOrCreateAccessControl(AccessControl adminAc, AccessControl currentAccessControl,
		AccessControlDAOInterface accessControlDAO, EntityWithAccessRights entity, Password thePassword, String access)
			throws GeneralSecurityException, UnsupportedEncodingException, SQLException {
		boolean allowRead = (access.indexOf('R') != -1);
		boolean allowModify = (access.indexOf('M') != -1);
		if( currentAccessControl == null ) {
			accessControlDAO.create(entity, thePassword, allowRead, allowModify);
			return true;
		} else if(updateAccessControl(adminAc, currentAccessControl, allowRead, allowModify)) {
			accessControlDAO.update(entity, currentAccessControl);
			return true;
		}

		return false;
	}

	private boolean updateAccessControl(AccessControl adminAc, AccessControl currentAccessControl,
										boolean allowRead, boolean allowModify) {
		boolean changed = false;
		if( allowRead && currentAccessControl.getReadKey() == null ) {
			currentAccessControl.setReadKey(adminAc.getReadKey());
			changed = true;
		}
		if( allowModify && currentAccessControl.getModifyKey() == null ) {
			currentAccessControl.setModifyKey(adminAc.getModifyKey());
			changed = true;
		}
		if( !allowModify && currentAccessControl.getModifyKey() != null ) {
			currentAccessControl.setModifyKey(null);
			changed = true;
		}
		return changed;
	}

    @Override
	public String getServletInfo() {
        return "Updates the access a user has to a password";
    }

}
