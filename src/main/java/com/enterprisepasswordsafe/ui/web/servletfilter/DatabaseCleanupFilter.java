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

/*
 * Filter.java
 *
 * Created on 22 July 2003, 12:09
 */

package com.enterprisepasswordsafe.ui.web.servletfilter;

import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import com.enterprisepasswordsafe.engine.Repositories;
import com.enterprisepasswordsafe.engine.database.BOMFactory;
import com.enterprisepasswordsafe.engine.database.exceptions.DatabaseUnavailableException;
import com.enterprisepasswordsafe.engine.dbpool.DatabasePool;
import com.enterprisepasswordsafe.engine.dbpool.DatabasePoolFactory;

/**
 * Filter to clean up any database connections.
 */

public final class DatabaseCleanupFilter implements Filter {
    @Override
	public void init(final FilterConfig config) {
        // Do nothing
    }

    @Override
    public void destroy() {
        // Do nothing
    }

    @Override
	public void doFilter(ServletRequest request, ServletResponse response,
            FilterChain next) throws ServletException, IOException {
    	try {
    		next.doFilter(request, response);
    	} finally {
            if(isPoolInitialised()) {
                try {
                    Connection currentConnection = BOMFactory.getCurrentConntection();
                    if (currentConnection != null && !currentConnection.isClosed()) {
                        Logger.getGlobal().log(Level.WARNING, "Reached cleanup filter with open connection.");
                        BOMFactory.closeCurrent();
                    }
                } catch (SQLException e) {
                    Logger.getGlobal().log(Level.SEVERE, "Problem attempting to check connection", e);
                }
            }
    	}
    }

    private boolean isPoolInitialised() {
        return Repositories.databasePoolFactory.isConfigured();
    }

}
