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

import javax.servlet.http.HttpServlet;

import com.enterprisepasswordsafe.ui.web.utils.ServletPaths;


/**
 * Base Servlet providing methods used by multiple servlets.
 *
 * @author Al Sutton
 */

public abstract class BaseServlet extends HttpServlet {

    /**
	 *
	 */
	private static final long serialVersionUID = -8090411218896250706L;

	/**
     * The default URL to send people to.
     */

    public static final String DEFAULT_URL = ServletPaths.getExplorerPath();

    /**
     * The attribute for the page title.
     */

    public static final String PAGE_TITLE_ATTRIBUTE = "page.title";

    /**
     * The attribute name for messages indicating success.
     */

    public static final String MESSAGE_ATTRIBUTE = "message";

    /**
     * The attribute name for messages indicating success.
     */

    public static final String ERROR_ATTRIBUTE = "error";

    /**
     * The attribute used to store the authentication sources list.
     */

    public static final String AUTH_SOURCE_LIST_ATTRIBUTE = "auth_list";

    /**
     * The attribute used to store the authentication source.
     */

    public static final String AUTH_SOURCE_ATTRIBUTE = "auth_source";

    /**
     * The parameter name used to pass information about the next page to visit.
     */

    public static final String NEXT_PAGE_PARAMETER = "next_page";

    /**
     * The attribute used to store a list of nodes.
     */

    public static final String NODE_LIST_PARAMETER = "node_list";

    /**
     * The attribute used to store the parents of a particular node.
     */
    public static final String NODE_PARENTAGE = "node_parents";

    /**
     * The parameter name used to hold dates and times.
     */

    public static final String DATE_TIME_PARAMETER = "dt";

    /**
     * The attribute used to store the children of a particular node.
     */
    public static final String NODE_CHILDREN = "node_children";

    /**
     * Parameter for holding start dates.
     */

    public static final String START_DATE_PARAMETER = "start_date";

    /**
     * Parameter for holding end dates.
     */

    public static final String END_DATE_PARAMETER = "end_date";

    /**
     * Attribute used to store a list of error messages.
     */

    public static final String ERROR_TEXT_LIST = "error_list";

    /**
     * The parameter used to store sort order information.
     */

    public static final String SORT_PARAMETER = "sortby";

    /**
     * The attribute name used to store a user.
     */

    public static final String USER_ATTRIBUTE = "user";

    /**
     * The parameter name used to store a username.
     */

    public static final String USERNAME_PARAMETER = "username";

    /**
     * The attribute name used to store a user.
     */

    public static final String NODE = "node";

    /**
     * The attribute name used to store a list of users.
     */

    public static final String USER_LIST = "users";

    /**
     * The attribute name to store the list of groups a user belongs to.
     */

    public static final String USERS_GROUP_LIST = "user.groups";

    /**
     * The attribute name to store a group ID.
     */

    public static final String GROUP = "group";

    /**
     * The attribute name to store a list of groups.
     */

    public static final String GROUPS_ATTRIBUTE = "groups";

    /**
     * Attribut name used to store a list of group members.
     */

    public static final String GROUP_MEMBERS = "group.members";

    /**
     * Attribute name used to store a list of users not part of a group.
     */

    public static final String GROUP_NON_MEMBERS = "group.non-members";

    /**
     * Attribute name used to store a list of group access controls.
     */
    public static final String GACS_ATTRIBUTE = "gacs";

    /**
     * Atrribute name used to store a list of user access controls.
     */
    public static final String UACS_ATTRIBUTE = "uacs";

    /**
     * Attribute name used to store a list of locations.
     */
    public static final String LOCATIONS = "locations";

    /**
     * Attribute name to store a count.
     */

    public static final String COUNT = "count";

    /**
     * The parameter name used to hold a date (format will always be yyyyMMdd).
     */

    public static final String DATE_PARAMETER = "date";

    /**
     * The parameter name used to hold a list of events.
     */

    public static final String EVENTS_PARAMETER = "events";

    /**
     * The parameter for any form of action.
     */

    public static final String ACTION_PARAMETER = "action";

    /**
     * The parameter for the full name of a user.
     */

    public static final String FULL_NAME_PARAMETER = "fn";

    /**
     * The parameter for an email address.
     */

    public static final String EMAIL_PARAMETER = "em";

    /**
     * The parameter used to hold the originally requested URI if the user is redirected
     * to the login screen by the authentication filter.
     */

	public static final String ORIGINAL_URI = "URI";

    /**
     * The parameter used to hold the originally request parameters if the user is redirected
     * to the login screen by the authentication filter.
     */

	public static final String ORIGINAL_PARAMETERS = "URI_PARAMS";
}
