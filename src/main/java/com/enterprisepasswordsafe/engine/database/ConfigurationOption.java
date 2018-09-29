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

package com.enterprisepasswordsafe.engine.database;

import com.enterprisepasswordsafe.engine.passwords.AuditingLevel;
import com.enterprisepasswordsafe.proguard.ExternalInterface;

public enum ConfigurationOption implements ExternalInterface {

    ALLOW_BACK_BUTTON_TO_ACCESS_PASSWORD("password.back_to_password_allowed", "false"),
    DAYS_BEFORE_EXPIRY_TO_WARN("EPASSWARN", null),
    DEFAULT_AUTHENTICATION_SOURCE_ID("user.default_auth_source", "0"),
    DEFAULT_LOGIN_ACCESS("user.login_access", UserIPZoneRestriction.ALLOW_STRING),
    DEFAULT_HIERARCHY_ACCESS_RULE("hierarchy.default_rule", Configuration.HIERARCHY_ACCESS_ALLOW),
    EDIT_USER_MINIMUM_USER_LEVEL("hierarchy.edit_userlevel", "A"),
    HIDDEN_PASSWORD_ENTRY("password.entry_hidden", "true"),
    HIDE_EMPTY_FOLDERS("hierarchy.hide_empty", Configuration.HIDE_EMPTY_FOLDERS_ON),
    MAX_FUTURE_EXPIRY_DISTANCE("expiry.max_distance", "0"),
    INCLUDE_USER_ON_AUDIT_EMAIL("audit.email_user", "n"),
    LOGIN_ATTEMPTS("user.login_attempts", "3"),
    PASSWORD_AUDIT_LEVEL("password.audit", AuditingLevel.CREATOR_CHOOSE.toString()),
    PASSWORD_DISPLAY("password.defaultdisplay", "s"),
    PASSWORD_DISPLAY_TYPE("password.displaytype", "i"),
    PASSWORD_HIDE_SYSTEM_SELECTOR("password.hidesystems", "n"),
    PASSWORD_ON_SCREEN_TIME("password.onscreen", "5"),
    PASSWORD_REASON_FOR_VIEWING_REQUIRED("password.reasonrequired","n"),
    PERMISSION_PRECEDENCE("perms.precendece", "U"),
    PROPERTY_SERVER_BASE_URL("server_base_url", null),
    RAR_LIFETIME("rarLifetime", "10"),
    REPORT_SEPARATOR("report.separator",","),
    REJECT_HISTORICAL_EXPIRY_DATES("expiry.allow_historical", "N"),
    SCHEMA_VERSION("schema.id", null),
    SESSION_TIMEOUT("session.timeout", "30"),
    SMTP_ENABLED("smtp.enabled", null),
    SMTP_HOST("smtphost", null),
    SMTP_TO_PROPERTY("smtpto", null),
    SMTP_FROM("smtpfrom", null),
    STORE_PASSWORD_HISTORY("password.history", Password.SYSTEM_PASSWORD_CREATOR_CHOOSE),
    SUBADMINS_HAVE_HISTORY_ACCESS("subadmin.access_history", "N"),
    VOTE_ON_OWN_RA_REQUESTS("rarSelfVote", "y");

    private String mPropertyName;
    private String mDefaultValue;

    ConfigurationOption(final String propertyName, final String defaultValue) {
        mPropertyName = propertyName;
        mDefaultValue = defaultValue;
    }

    public String getPropertyName() {
        return mPropertyName;
    }

    public String getDefaultValue() {
        return mDefaultValue;
    }
}
