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

package com.enterprisepasswordsafe.database;

/**
 * Object responsible for handling user configuration options.
 */
public class Configuration  {

    /**
     * The values for the hiding of the empty folder rule.
     */

    public static final String	HIDE_EMPTY_FOLDERS_ON = "Y";
    public static final String HIDE_EMPTY_FOLDERS_OFF = "N";
    /**
     * The different values for the default hierarchy access rule.
     */

    public static final String	HIERARCHY_ACCESS_ALLOW = "A";
    public static final String HIERARCHY_ACCESS_DENY = "D";

    /**
     * Private constructor to prevent construction by other objects.
     */

    protected Configuration() {
    }
}
