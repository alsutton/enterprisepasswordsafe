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

import java.io.IOException;
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

import com.enterprisepasswordsafe.engine.database.AccessControl;
import com.enterprisepasswordsafe.engine.database.AccessRole;
import com.enterprisepasswordsafe.engine.database.Group;
import com.enterprisepasswordsafe.engine.database.GroupAccessControl;
import com.enterprisepasswordsafe.engine.database.GroupAccessControlDAO;
import com.enterprisepasswordsafe.engine.database.GroupAccessRoleDAO;
import com.enterprisepasswordsafe.engine.database.GroupDAO;
import com.enterprisepasswordsafe.engine.database.Membership;
import com.enterprisepasswordsafe.engine.database.MembershipDAO;
import com.enterprisepasswordsafe.engine.database.Password;
import com.enterprisepasswordsafe.engine.database.PasswordDAO;
import com.enterprisepasswordsafe.engine.database.TamperproofEventLog;
import com.enterprisepasswordsafe.engine.database.TamperproofEventLogDAO;
import com.enterprisepasswordsafe.engine.database.User;
import com.enterprisepasswordsafe.engine.database.UserAccessControl;
import com.enterprisepasswordsafe.engine.database.UserAccessControlDAO;
import com.enterprisepasswordsafe.engine.database.UserAccessRoleDAO;
import com.enterprisepasswordsafe.engine.database.UserDAO;
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

    public static final String USER_PARAMETER_PREFIX = "u_";

    /**
     * The size of the user parameter prefix
     */

    private static final int USER_PARAMETER_PREFIX_LENGTH = USER_PARAMETER_PREFIX.length();

    /**
     * The prefix for a user parameter.
     */

    public static final String GROUP_PARAMETER_PREFIX = "g_";

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
            throws IOException, ServletException {
    	try {
	    	User adminUser = SecurityUtils.getRemoteUser(request);
	        ServletUtils servletUtils = ServletUtils.getInstance();
	        if (!adminUser.isAdministrator() &&  !adminUser.isSubadministrator()) {
	        	servletUtils.generateErrorMessage(request, "You can not modify access to this password");
                response.sendRedirect(request.getContextPath() + ERROR_PAGE);
	        	return;
	        }

	        String passwordId = servletUtils.getParameterValue(request, SharedParameterNames.PASSWORD_ID_PARAMETER);

	        // Verify the access control is in place
	        Group adminGroup = GroupDAO.getInstance().getAdminGroup(adminUser);
	        AccessControl ac = GroupAccessControlDAO.getInstance().getGac(adminGroup, passwordId);
	        if( ac == null
	        ||	ac.getReadKey() == null
	        ||  ac.getModifyKey() == null ) {
	        	servletUtils.generateErrorMessage(request, "You can not modify access to the specified password");
                response.sendRedirect(request.getContextPath() + ERROR_PAGE);
	        	return;
	        }

	        Password password = PasswordDAO.getInstance().getByIdEvenIfDisabled(ac, passwordId);
	        User theAdmin = UserDAO.getInstance().getAdminUser(adminGroup);

	        boolean sendEmailAlert = ((password.getAuditLevel() & Password.AUDITING_EMAIL_ONLY)!=0);

			Enumeration<String> params = request.getParameterNames();
	    	while( params.hasMoreElements() ) {
	    		String thisParameter = params.nextElement();

	    		String value = request.getParameter(thisParameter);

	    		if			( thisParameter.startsWith(USER_PARAMETER_PREFIX) ) {
	    			handleUserParameter(adminGroup, adminUser, password, ac, thisParameter, value);
	    		} else if	( thisParameter.startsWith(GROUP_PARAMETER_PREFIX) ) {
	    			handleGroupParameter(theAdmin, adminGroup, adminUser, password, ac, thisParameter, value);
				}
	    	}

	    	processUserHistoryRoles(adminUser, password, request, sendEmailAlert);
	    	processUserRARoles(adminUser, password, request, sendEmailAlert);
	    	processGroupHistoryRoles(adminUser, password, request, sendEmailAlert);
	    	processGroupRARoles(adminUser, password, request, sendEmailAlert);

	    	servletUtils.generateMessage(request, "The password access rights were updated.");
	    	response.sendRedirect(request.getContextPath()+"/subadmin/AlterAccess?id="+password.getId());
    	} catch(Exception ex) {
    		throw new ServletException("The access rules could not be updated due to an error.", ex);
    	}


    }

    /**
     * Handle a user parameter.
     * @throws GeneralSecurityException
     * @throws SQLException
     * @throws UnsupportedEncodingException
     */

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

    /**
     * Handle a group parameter.
     *
     * @throws GeneralSecurityException
     * @throws SQLException
     * @throws UnsupportedEncodingException
     */

    private void handleGroupParameter(final User theAdmin,
    		final Group adminGroup, final User adminUser,
    		final Password password, final AccessControl ac,
    		final String thisParameter, final String value )
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

    /**
     * Process the user restricted access role settings.
     *
     * @param remoteUser The user making the change.
     * @param password The password the role is for.
     * @param request The request being serviced.
     * @param sendEmailAlert whether or not email alerts should be sent.
     */

    private void processUserRARoles(final User remoteUser, final Password password,
    		final HttpServletRequest request, final boolean sendEmailAlert)
    throws UnsupportedEncodingException, SQLException, GeneralSecurityException {
    	processUserRoles(remoteUser, password,
        		request, sendEmailAlert, "our_", "ur_",
        		"approved restricted access requests",
				AccessRole.APPROVER_ROLE);
    }

    /**
     * Process the group restricted access role settings.
     *
     * @param remoteUser The user making the change.
     * @param password The password the role is for.
     * @param request The request being serviced.
     * @param sendEmailAlert whether or not email alerts should be sent.
     */

    private void processGroupRARoles(final User remoteUser, final Password password,
    		final HttpServletRequest request, final boolean sendEmailAlert)
    throws UnsupportedEncodingException, SQLException, GeneralSecurityException {
    	processGroupRoles(remoteUser, password,
        		request, sendEmailAlert, "ogr_", "gr_",
        		"approved restricted access requests",
				AccessRole.APPROVER_ROLE);
    }


    /**
     * Process the user history role settings.
     *
     * @param remoteUser The user making the change.
     * @param password The password the role is for.
     * @param request The request being serviced.
     * @param sendEmailAlert whether or not email alerts should be sent.
     */

    private void processUserHistoryRoles(final User remoteUser, final Password password,
    		final HttpServletRequest request, final boolean sendEmailAlert)
    throws UnsupportedEncodingException, SQLException, GeneralSecurityException {
    	processUserRoles(remoteUser, password,
        		request, sendEmailAlert, "ouh_", "uh_",
        		"view the password history",
				AccessRole.HISTORYVIEWER_ROLE);
    }

    /**
     * Process the group history role settings.
     *
     * @param remoteUser The user making the change.
     * @param password The password the role is for.
     * @param request The request being serviced.
     * @param sendEmailAlert whether or not email alerts should be sent.
     */

    private void processGroupHistoryRoles(final User remoteUser, final Password password,
    		final HttpServletRequest request,
    		final boolean sendEmailAlert)
    throws UnsupportedEncodingException, SQLException, GeneralSecurityException {
    	processGroupRoles(remoteUser, password,
        		request, sendEmailAlert, "ogh_", "gh_",
        		"view the password history",
				AccessRole.HISTORYVIEWER_ROLE);
    }

    /**
     * Process the roles for a user
     *
     * @param remoteUser The user making the change.
     * @param password The password the role is for.
     * @param request The request being serviced.
     * @param sendEmailAlert whether or not email alerts should be sent.
     */

    private void processUserRoles(final User remoteUser, final Password password,
    		final HttpServletRequest request, final boolean sendEmailAlert,
    		final String originalPrefix, final String setPrefix,
    		final String roleDescription, final String role)
    throws UnsupportedEncodingException, SQLException, GeneralSecurityException {
        List<String> onNow = new ArrayList<String>();
        List<String> previouslyOn = new ArrayList<String>();

		Enumeration<String> params = request.getParameterNames();
        while( params.hasMoreElements() ) {
    		String thisParameter = params.nextElement();

    		if	( thisParameter.startsWith(originalPrefix)) {
    			previouslyOn.add(thisParameter.substring(4));
    		} else if	( thisParameter.startsWith(setPrefix)) {
    			onNow.add(thisParameter.substring(3));
    		}
    	}

    	for(String id : onNow) {
    		if(previouslyOn.contains(id)) {
    			previouslyOn.remove(id);
    			continue;
    		}
    		giveUserRole(remoteUser, password, id, roleDescription, role, sendEmailAlert);
    	}

    	for(String id: previouslyOn) {
    		removeUserRole(remoteUser, password, id, roleDescription, role, sendEmailAlert);
    	}
    }

    /**
     * Process the roles for a group
     *
     * @param remoteUser The user making the change.
     * @param password The password the role is for.
     * @param request The request being serviced.
     * @param sendEmailAlert whether or not email alerts should be sent.
     */

    private void processGroupRoles(final User remoteUser, final Password password,
    		final HttpServletRequest request, final boolean sendEmailAlert,
			final String originalPrefix, final String setPrefix,
			final String roleDescription, final String role)
    throws UnsupportedEncodingException, SQLException, GeneralSecurityException {
        List<String> onNow = new ArrayList<String>();
        List<String> previouslyOn = new ArrayList<String>();

		Enumeration<String> params = request.getParameterNames();
        while( params.hasMoreElements() ) {
    		String thisParameter = params.nextElement();

    		if	( thisParameter.startsWith(originalPrefix)) {
    			previouslyOn.add(thisParameter.substring(4));
    		} else if	( thisParameter.startsWith(setPrefix)) {
    			onNow.add(thisParameter.substring(3));
    		}
    	}

    	for(String id : onNow) {
    		if(previouslyOn.contains(id)) {
    			previouslyOn.remove(id);
    			continue;
    		}
    		giveGroupRole(remoteUser, password, id, roleDescription, role, sendEmailAlert);
    	}

    	for(String id: previouslyOn) {
    		removeGroupRole(remoteUser, password, id, roleDescription,role, sendEmailAlert);
    	}
    }

    /**
     * Give a role to a user
     *
     * @throws GeneralSecurityException
     * @throws SQLException
     * @throws UnsupportedEncodingException
     */

    private void giveUserRole(final User remoteUser, final Password password, final String userId,
    		final String roleName, final String role, final boolean sendEmailAlert)
    throws UnsupportedEncodingException, SQLException, GeneralSecurityException {
    	TamperproofEventLogDAO.getInstance().create(
				TamperproofEventLog.LOG_LEVEL_OBJECT_MANIPULATION,
				remoteUser,
				password,
                "Gave the user {user:"+userId+"} the right to "+roleName,
				sendEmailAlert);
		UserAccessRoleDAO.getInstance().create( password.getId(), userId, role );
    }

    /**
     * Remove a role from a user
     *
     * @throws GeneralSecurityException
     * @throws SQLException
     * @throws UnsupportedEncodingException
     */

    private void removeUserRole(final User remoteUser, final Password password, final String userId,
    		final String roleName, final String role, final boolean sendEmailAlert)
    throws UnsupportedEncodingException, SQLException, GeneralSecurityException {
		TamperproofEventLogDAO.getInstance().create(
				TamperproofEventLog.LOG_LEVEL_OBJECT_MANIPULATION,
				remoteUser,
				password,
                "Removed the right to "+roleName+" from the user {user:"+userId+"}",
				sendEmailAlert);
		UserAccessRoleDAO.getInstance().delete( password.getId(), userId, role );
    }

    /**
     * Give a role to a user
     *
     * @throws GeneralSecurityException
     * @throws SQLException
     * @throws UnsupportedEncodingException
     */

    private void giveGroupRole(final User remoteUser, final Password password, final String groupId,
    		final String roleName, final String role, final boolean sendEmailAlert)
    throws UnsupportedEncodingException, SQLException, GeneralSecurityException {
    	TamperproofEventLogDAO.getInstance().create(
				TamperproofEventLog.LOG_LEVEL_OBJECT_MANIPULATION,
				remoteUser,
				password,
                "Gave the group {group:"+groupId+"} the right to "+roleName,
				sendEmailAlert);
		GroupAccessRoleDAO.getInstance().create( password.getId(), groupId, role );
    }

    /**
     * Remove a role from a user
     *
     * @throws GeneralSecurityException
     * @throws SQLException
     * @throws UnsupportedEncodingException
     */

    private void removeGroupRole(final User remoteUser,
    		final Password password, final String groupId, final String roleName, final String role,
    		final boolean sendEmailAlert)
    throws UnsupportedEncodingException, SQLException, GeneralSecurityException {
		TamperproofEventLogDAO.getInstance().create(
				TamperproofEventLog.LOG_LEVEL_OBJECT_MANIPULATION,
				remoteUser,
				password,
                "Removed the right to "+roleName+" from the group {group:"+groupId+"}",
				sendEmailAlert);
		GroupAccessRoleDAO.getInstance().delete(password.getId(), groupId, role);
    }


    /**
     * Change the access a user has to a password.
     *
     * @param adminUser The admin user making the change.
     * @param adminAc The admin access control to access the password.
     * @param thePassword The password whose access is being change.
     * @param theUser The user whose access is being changed.
     * @param access The new access rights.
     */

    private void changeAccess(final User adminUser, final AccessControl adminAc, final Password thePassword,
    		final User theUser, final String access )
    	throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        // Get the existing UAC (if it exists);
        UserAccessControl currentUac = UserAccessControlDAO.getInstance().getUac(theUser, thePassword);
        if (access.equals("N") ) {
        	if( currentUac != null ) {
            	boolean sendEmail = ((thePassword.getAuditLevel() & Password.AUDITING_EMAIL_ONLY)!=0);
        		TamperproofEventLogDAO.getInstance().create(
						TamperproofEventLog.LOG_LEVEL_OBJECT_MANIPULATION,
        				adminUser,
        				thePassword,
        				"Removed all permissions for "+theUser.getUserName(),
        				sendEmail
    				);
        		UserAccessControlDAO.getInstance().delete(currentUac);
        	}

        	return;
        }

        // Get the admin UAC for the password and decrypt the password
        // contents
        // Construct the new permissions for the UAC
    	boolean allowRead = (access.indexOf('R') != -1);
    	boolean allowModify = (access.indexOf('M') != -1);

    	if( currentUac != null ) {
        	boolean changed = false;
        	if( allowRead && currentUac.getReadKey() == null ) {
        		currentUac.setReadKey(adminAc.getReadKey());
        		changed = true;
        	}
        	if( allowModify && currentUac.getModifyKey() == null ) {
        		currentUac.setModifyKey(adminAc.getModifyKey());
        		changed = true;
        	}
        	if( !allowModify && currentUac.getModifyKey() != null ) {
        		currentUac.setModifyKey(null);
        		changed = true;
        	}

        	if(!changed) {
        		return;
        	}
    	}

    	boolean sendEmail = ((thePassword.getAuditLevel() & Password.AUDITING_EMAIL_ONLY)!=0);
    	TamperproofEventLogDAO.getInstance().create(
				TamperproofEventLog.LOG_LEVEL_OBJECT_MANIPULATION,
    			adminUser,
    			thePassword,
                "Changed the access permissions on the user {user:"
                    + theUser.getUserId()
                    + "} to be "
                    + access,
              	sendEmail);

        if (currentUac != null) {
            UserAccessControlDAO.getInstance().update(currentUac, theUser);
        } else {
        	UserAccessControlDAO.getInstance().create(
        			theUser,
        			thePassword,
        			allowRead,
        			allowModify
    			);
        }
    }

    /**
     * Change the access a group has to a password.
     *
     * @param adminUser The admin user making the change.
     * @param adminAc The admin access control to access the password.
     * @param thePassword The password whose access is being change.
     * @param theGroup The user whose access is being changed.
     * @param access The new access rights.
     */

    private void changeAccess(final User adminUser, final AccessControl adminAc, final Password thePassword,
    		final Group theGroup, final String access )
    	throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
    	// Look for an existing group access control to modify
    	GroupAccessControlDAO gacDAO = GroupAccessControlDAO.getInstance();
    	GroupAccessControl currentGac = gacDAO.getGac( adminUser, theGroup, thePassword );

	    if (access.equals("N")) {
	    	if( currentGac != null ) {
	    		gacDAO.delete(currentGac);
            	boolean sendEmail = ((thePassword.getAuditLevel() & Password.AUDITING_EMAIL_ONLY)!=0);
	    		TamperproofEventLogDAO.getInstance().create(
    					TamperproofEventLog.LOG_LEVEL_OBJECT_MANIPULATION,
		        		adminUser,
		        		thePassword,
		                "Removed all permissions for the group {group:"+theGroup.getGroupId()+"}",
		                sendEmail
		        	);
	    	}

	    	return;
	    }

    	boolean allowRead = (access.indexOf('R') != -1);
    	boolean allowModify = (access.indexOf('M') != -1);

        if( currentGac == null) {
            gacDAO.create(theGroup, thePassword, allowRead, allowModify);
            return;
        }


        boolean changed = false;
        if( allowRead && currentGac.getReadKey() == null ) {
            currentGac.setReadKey(adminAc.getReadKey());
            changed = true;
        }
        if( allowModify && currentGac.getModifyKey() == null ) {
            currentGac.setModifyKey(adminAc.getModifyKey());
            changed = true;
        }
        if( !allowModify && currentGac.getModifyKey() != null ) {
            currentGac.setModifyKey(null);
            changed = true;
        }

        if(!changed) {
            return;
        }

    	boolean sendEmail = ((thePassword.getAuditLevel() & Password.AUDITING_EMAIL_ONLY)!=0);
    	TamperproofEventLogDAO.getInstance().create(
				TamperproofEventLog.LOG_LEVEL_OBJECT_MANIPULATION,
    			adminUser,
    			thePassword,
        		"Changed the access permissions on the group {group:"
	                + theGroup.getGroupId()
	                + "} to be "
	                + access,
	         	sendEmail);

        gacDAO.update(theGroup, currentGac);
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */

    @Override
	public String getServletInfo() {
        return "Updates the access a user has to a password";
    }

}
