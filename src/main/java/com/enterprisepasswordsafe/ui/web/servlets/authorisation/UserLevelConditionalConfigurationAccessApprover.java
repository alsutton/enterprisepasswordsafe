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

package com.enterprisepasswordsafe.ui.web.servlets.authorisation;

import java.sql.SQLException;

import com.enterprisepasswordsafe.engine.database.ConfigurationDAO;
import com.enterprisepasswordsafe.engine.database.ConfigurationOption;
import com.enterprisepasswordsafe.engine.database.User;

/**
 * AccessApprover which determines access based on a configuration option.
 */
public class UserLevelConditionalConfigurationAccessApprover implements AccessApprover {

	private final ConfigurationOption mProperty;

	public UserLevelConditionalConfigurationAccessApprover(final ConfigurationOption property) {
		mProperty = property;
	}

	@Override
	public boolean isAuthorised(final User theUser) throws SQLException {
		String requiredLevel = ConfigurationDAO.getValue(mProperty);
		if(requiredLevel.equals("A")) {
			return theUser.isAdministrator();
		}
		if(requiredLevel.equals("S")) {
			return theUser.isSubadministrator() || theUser.isAdministrator();
		}
		return requiredLevel.equals("U");
	}

}
