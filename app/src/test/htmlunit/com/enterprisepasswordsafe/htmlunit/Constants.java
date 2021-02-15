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

package com.enterprisepasswordsafe.htmlunit;

public class Constants {

    /**
     * The host section of the URL
     */

    public static final String WEBAPP_HOST = "http://localhost:8080";

    /**
     * The context path for the webapp
     */

    private static final String WEBAPP_CONTEXT_PATH="/passwordsafe/";

    /**
     * The Raw API paths
     */

    public static final class RawAPI {
        private static final String API_BASE = WEBAPP_HOST + WEBAPP_CONTEXT_PATH + "api/";

        public static final String FIND_IDS_ENDPOINT = API_BASE + "FindIds";
        public static final String GET_PASSWORD_ENDPOINT = API_BASE + "GetPassword";
        public static final String UPDATE_PASSWORD_ENDPOINT = API_BASE + "UpdatePassword";
    }

    /**
     * The Web UI paths
     */

    public static final class WebUI {
        private static final String WEB_UI_BASE = WEBAPP_HOST + WEBAPP_CONTEXT_PATH;

        /**
         * The areas of the webapp, relative to the context root.
         */

        public static final String  ADMIN_AREA = "admin/",
                                    INCLUDES_AREA = "includes/",
                                    SUBADMIN_AREA = "subadmin/",
                                    SYSTEM_AREA = "system/";

        /**
         * URLS of the areas within the Web UI.
         */

        public static final String  ADMIN_URL = WEB_UI_BASE + ADMIN_AREA,
                                    INCLUDES_URL = WEB_UI_BASE + INCLUDES_AREA,
                                    SUBADMIN_URL = WEB_UI_BASE + SUBADMIN_AREA,
                                    SYSTEM_URL = WEB_UI_BASE + SYSTEM_AREA;

        /**
         * Base paths used for link identification in HtmlUnit tests
         */

        public static final String  ADMIN_BASE = WEBAPP_CONTEXT_PATH+ADMIN_AREA,
                                    SUBADMIN_BASE = WEBAPP_CONTEXT_PATH+SUBADMIN_AREA,
                                    SYSTEM_BASE = WEBAPP_CONTEXT_PATH+SYSTEM_AREA;

        /**
         * URLs the user will access directly
         */

        public static final String LOGIN_PAGE = WEB_UI_BASE+"Login";

        /**
         * Links used by HtmlUnit for testing
         */

        public static final String  AUTH_SOURCES_LINK = ADMIN_BASE + "AuthSources",
                                    AUTH_SOURCES_STAGE1_LINK = ADMIN_BASE + "AddAuthSourceStage1",
                                    CONFIGURE_LINK = ADMIN_BASE + "Configure",
                                    CONFIGURE_EMAIL_LINK = ADMIN_BASE + "ConfigureEmail",
                                    CUSTOM_FIELDS_LINK = ADMIN_BASE + "CustomFields",
                                    CREATE_PASSWORD_LINK = SYSTEM_BASE + "CreatePassword",
                                    EDIT_IPZONES_LINK = ADMIN_BASE + "EditIPZones",
                                    EDIT_HIERARCHY_LINK = SUBADMIN_BASE + "EditHierarchy",
                                    EXPLORER_LINK = SYSTEM_BASE + "Explorer",
                                    EVENT_LOG_LINK = ADMIN_BASE + "ViewEvents",
                                    GROUPS_CREATE_LINK = ADMIN_BASE + "CreateGroup",
                                    GROUPS_EDIT_LINK = ADMIN_BASE + "EditGroup",
                                    GROUPS_IMPORT_LINK = ADMIN_BASE + "ImportGroupFile",
                                    GROUPS_VIEW_LINK = ADMIN_BASE + "ViewGroups",
                                    LOGOUT_LINK = WEBAPP_CONTEXT_PATH + "Logout",
                                    NODE_GROUP_PERMISSIONS_LINK = SUBADMIN_BASE + "NodeGroupPermissions",
                                    NODE_USER_PERMISSIONS_LINK = SUBADMIN_BASE + "NodeUserPermissions",
                                    NODE_PASSWORD_DEFAULTS_LINK = SUBADMIN_BASE + "NodePasswordDefaults",
                                    PERSONAL_NODE_VIEW_LINK = SYSTEM_BASE + "ViewPersonalFolder",
                                    PROFILE_LINK = SYSTEM_BASE + "Profile",
                                    PASSWORD_RESTRICTIONS_LINK = ADMIN_BASE + "PasswordRestrictions",
                                    PASSWORD_RESTRICTIONS_ADD_STAGE1_LINK = ADMIN_BASE + "PasswordRestrictionsAddStage1",
                                    PASSWORDS_IMPORT_LINK = SUBADMIN_BASE + "ImportPasswordFile",
                                    RESTRICTED_ACCESS_REQUEST_LINK = SYSTEM_BASE + "ViewRARequests",
                                    SEARCH_LINK = SYSTEM_BASE + "Search",
                                    SEARCH_LOCATION_LINK = SYSTEM_BASE + "SearchLocation",
                                    USERS_EDIT_LINK = ADMIN_BASE + "User",
                                    USERS_IMPORT_LINK = ADMIN_BASE + "ImportUserFile",
                                    USERS_VIEW_LINK = ADMIN_BASE + "ViewUsers";

        /**
         * Servlets the user should be routed through. These should not be accessed
         * directly unless testing security.
         */

        public static final String  CREATE_PASSWORD_SERVLET = SYSTEM_URL + "CreatePassword",
                                    LOGIN_SERVLET = WEB_UI_BASE + "Login",
                                    PROFILE_SERVLET = SYSTEM_URL + "Profile";

    }

}
