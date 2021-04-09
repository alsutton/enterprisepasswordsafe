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

package com.enterprisepasswordsafe.engine.integration;

import java.sql.Connection;
import java.util.List;
import java.util.Map;

/**
 * The interface implemented by any class which can change the password
 * on a remote machine.
 */
public interface PasswordChanger {
	
	/**
	 * The property name for the password username.
	 */

	String USERNAME_PROPERTY = "username";
	
	/**
	 * The property name for the passwords' old password.
	 */

	String OLD_PASSWORD = "old_password";
	
	/**
	 * The property name for the passwords' new password.
	 */

	String NEW_PASSWORD = "new_password";
	
	/**
	 * The property name for the passwords' system.
	 */

	String SYSTEM = "system";
	
	/**
	 * Change a specific passsword.
	 * 
	 * @param conn The connection to the database.
	 * @param pluginProperties The properties configured by the EPS administrator.
	 * @param passwordProperties The properties relating to the password to change.
	 * @param script The script to run.
	 *
	 */

	void rollbackChange(Connection conn, Map<String, String> pluginProperties,
						Map<String, String> passwordProperties, String script)
	;

	/**
	 * Rollback a password change. This is usually called if a password change 
	 * further down the chain fails.
	 * 
	 * @param conn The connection to tyhe database.
	 * @param pluginProperties The properties configured by the EPS administrator.
	 * @param passwordProperties The properties relating to the password to change.
	 * @param script The script originally executed.
	 *
	 */

	void changePassword(Connection conn, Map<String, String> pluginProperties,
						Map<String, String> passwordProperties, String script)
	;

	/**
	 * Get the List of PasswordChangerProperty's which this plugin requires.
	 *
	 * @return The List of ChangerProperties.
	 */

	List<PasswordChangerProperty> getProperties();
	
	/**
	 * Method executed when the integration module is installed.
	 * 
	 * @param conn The connection to the database.
	 */

	void install(Connection conn);
	
	/**
	 * Method executed when the integration module is uninstalled.
	 * 
	 * @param conn The connection to the database.
	 */

	void uninstall(Connection conn);
}
