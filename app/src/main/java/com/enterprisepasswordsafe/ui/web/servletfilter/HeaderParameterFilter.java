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

package com.enterprisepasswordsafe.ui.web.servletfilter;

import com.enterprisepasswordsafe.model.dao.ConfigurationDAO;
import com.enterprisepasswordsafe.model.ConfigurationListeners;
import com.enterprisepasswordsafe.model.ConfigurationOptions;
import com.enterprisepasswordsafe.engine.Repositories;
import com.enterprisepasswordsafe.engine.utils.DateFormatter;

import javax.servlet.*;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;


public final class HeaderParameterFilter
	implements Filter, ConfigurationListeners.ConfigurationListener {

    /**
     * The timeout parameter.
     */

    public static final String TIMEOUT_PARAMETER = "timeout";

	/**
	 * The timeout for the cached values.
	 */

	private static final long CACHE_TIMEOUT = 60000;	// 1 minute.

	/**
	 * The last update for the cache.
	 */

	private static long cacheLastUpdate = 0;

    /**
     * The cahced session timeout value.
     */

    private static String sessionTimeoutCache;

	/**
	 * The object used to synchroized the fetching of the
	 * stylesheet URL.
	 */

	private static final Object SYNC_OBJECT = new Object();

    @Override
	public void init(final FilterConfig config) {
    	setTimeout(ConfigurationOptions.SESSION_TIMEOUT.getDefaultValue());

    	ConfigurationListeners.addListener(ConfigurationOptions.SESSION_TIMEOUT.getPropertyName(), this);
    }

    @Override
	public void doFilter(ServletRequest request, ServletResponse response,
            FilterChain next) throws IOException, ServletException {
    	long now = System.currentTimeMillis();
    	if( now - cacheLastUpdate > CACHE_TIMEOUT ) {
			updateCachedTimeout();
    	}

    	request.setAttribute(TIMEOUT_PARAMETER, sessionTimeoutCache);

    	HttpServletResponse httpResponse = (HttpServletResponse) response;
    	httpResponse.addHeader("Cache-Control", "no-cache, no-store, must-revalidate, max-age=0");
    	httpResponse.addHeader("Expires", "0");
    	httpResponse.addHeader("Pragma", "no-cache");
        httpResponse.addHeader("X-Frame-Options", "DENY");
        httpResponse.addHeader("Content-Security-Policy", "default-src 'self'; frame-src 'none'; object-src 'none'");

        next.doFilter(request, response);
    }

    @Override
	public void destroy() {
    }

	private void updateCachedTimeout() {
		synchronized(SYNC_OBJECT) {
			long now = System.currentTimeMillis();
			if( now - cacheLastUpdate > CACHE_TIMEOUT ) {
				try {
					updateParameters();
				} catch(SQLException sqle) {
					Logger.
							getLogger(getClass().toString()).
							log(Level.SEVERE, "Error updating parameters", sqle);
				}
			}
			cacheLastUpdate = System.currentTimeMillis();
		}
	}

    private void updateParameters()
    	throws SQLException {
		// Don't try to refresh using an invalid database pool
    	if( ! Repositories.databasePoolFactory.isConfigured() ) {
    		return;
    	}

       	updateTimeout();
    }

    public void updateTimeout()
    	throws SQLException {
    	String sessionTimeout = ConfigurationDAO.getValue(ConfigurationOptions.SESSION_TIMEOUT);
	    if (sessionTimeout != null && sessionTimeout.length() > 0) {
		    setTimeout(sessionTimeout);
	    }
    }

    private static synchronized void setTimeout(String timeout) {
	    try {
	    	int value = Integer.parseInt(timeout) - 1;
	    	value *= DateFormatter.MILLIS_IN_MINUTE;
	    	sessionTimeoutCache = Integer.toString(value);
	    } catch (Exception ex) {
	    	Logger.
	    		getAnonymousLogger().
	    			log(Level.SEVERE, "Error updating timeout cache", ex);
	    }
    }

	@Override
	public void configurationChange(String propertyName, String propertyValue) {
		if	( propertyName.equals(ConfigurationOptions.SESSION_TIMEOUT.getPropertyName()) ) {
			setTimeout( propertyValue );
		}
	}
}
