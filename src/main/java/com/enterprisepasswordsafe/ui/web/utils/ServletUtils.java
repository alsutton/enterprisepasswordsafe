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

package com.enterprisepasswordsafe.ui.web.utils;

import com.enterprisepasswordsafe.ui.web.servlets.BaseServlet;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

public final class ServletUtils {

	/**
     * The parameter used to pass group IDs.
     */

    public static final String GROUP_ID_PARAMETER = "group_id";

    /**
     * Parameter/Attribute name used to store a node ID.
     */

    public static final String NODE_ID_PARAMETER = "nodeId";

    /**
     * Retrieves a parameter value by first checking the requests parameter
     * map, and then checking the requests attribute.
     *
     * @param request
     *            The HttpServletRequest object to check.
     * @param parameterName
     *            The parameter name to check for.
     * @return The value of the parameter (or null if there is no parameter).
     */

    public String getParameterValue(final HttpServletRequest request, final String parameterName) {
        String value = (String) request.getAttribute(parameterName);
        if (value == null || value.length() == 0)
            value = request.getParameter(parameterName);
        if (value == null || value.length() == 0) {
            HttpSession session = request.getSession(false);
            if (session != null) {
                value = (String) session.getAttribute(parameterName);
            }
        }

        return value;
    }

    /**
     * Gets the Group ID related to a request
     *
     * @param request The servlet request.
     * @return The group ID from the request, or null if one was supplied.
     */

    public String getGroupId(final HttpServletRequest request) {
        return getParameterValue(request, GROUP_ID_PARAMETER);
    }

    /**
     * Gets the node ID related to a request
     *
     * @param request The servlet request.
     * @return The node ID from the request, or null if one was supplied.
     */

    public String getNodeId(final HttpServletRequest request) {
        return getParameterValue(request, NODE_ID_PARAMETER);
    }

    /**
     * Sets the current node ID
     */

    public void setCurrentNodeId(final HttpServletRequest request, final String nodeId) {
    	request.getSession().setAttribute(NODE_ID_PARAMETER, nodeId);
    }

    /**
     * Sets a request attribute to a value. Before the value is set the
     * method checks the requests parameters to see if there is a value
     * set for a parameter with the same name, if there is it will
     * use the parameter value instead of the specified value.
     *
     * @param request
     * 				The request being serviced.
     * @param paramName
     * 				The name of the parameter to set.
     * @param defaultValue
     * 				The value to set if no value is found in the request parameters.
     */

    public void setAttributeAllowingOverride( final HttpServletRequest request,
    		final String paramName, final String defaultValue ) {
    	String value = request.getParameter(paramName);
    	if( value == null || value.length() == 0 ) {
    		value = defaultValue;
    	}

    	request.setAttribute(paramName, value);
    }

    /**
     * Copies a parameter from the incoming request parameters to the
     * request attributes for use by struts bean:write.
     */

    public void copyParameterToAttribute(final HttpServletRequest request,
    		final String parameter) {
    	String defaultValue = (String) request.getAttribute(parameter);
    	if(defaultValue == null) {
    		defaultValue="";
    	}
    	copyParameterToAttribute(request, parameter, defaultValue);
    }

    /**
     * Copies a parameter from the incoming request parameters to the
     * request attributes for use by struts bean:write.
     */

    public void copyParameterToAttribute(final HttpServletRequest request,
    		final String parameter, final String defaultValue) {
    	String value = request.getParameter(parameter);
    	if( value == null ) {
    		value = defaultValue;
    	}
    	request.setAttribute(parameter, value);
    }

    /**
     * Copies a parameter from the incoming request parameters to the
     * request attributes for use by struts bean:write.
     */

    public void copyParameterToAttributeIfNotEmpty(final HttpServletRequest request, final String parameter) {
    	String value = request.getParameter(parameter);
    	if( value.isEmpty() ) {
    		return;
    	}
    	request.setAttribute(parameter, value);
    }

    /**
     * Constructs an error message and stores it in the request.
     *
     * @param request
     *            The request being serviced.
     * @param message
     *            The message summarising the problem.
     */

    public void generateMessage(final HttpServletRequest request, final String message) {
        request.getSession(true).setAttribute(BaseServlet.MESSAGE_ATTRIBUTE, message);
    }

    /**
     * Constructs an error message and stores it in the request.
     *
     * @param request
     *            The request being serviced.
     * @param message
     *            The message summarising the problem.
     */

    public void generateErrorMessage(final HttpServletRequest request, final String message) {
    	request.getSession(true).setAttribute(BaseServlet.ERROR_ATTRIBUTE, message);
    }

    /**
     * Constructs an error message and stores it in the request.
     *
     * @param request
     *            The request being serviced.
     * @param message
     *            The message summarising the problem.
     * @param excpt
     *            The exception holding the message.
     */

    public void generateErrorMessage(final HttpServletRequest request,
    		final String message, final Exception excpt) {
        StringBuilder messageBuffer = new StringBuilder(80);
        messageBuffer.append(message);
        messageBuffer.append("\n(");
        messageBuffer.append(excpt.getMessage());
        messageBuffer.append(").");
        generateErrorMessage(request, messageBuffer.toString());
    }

    //---------------------

    private static final class SingletonHolder {
    	private static final ServletUtils INSTANCE = new ServletUtils();
    }

    public static ServletUtils getInstance() {
    	return SingletonHolder.INSTANCE;
    }

}
