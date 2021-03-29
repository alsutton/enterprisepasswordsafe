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

package com.enterprisepasswordsafe.authentication.jaas;

import java.security.Principal;

/**
 * Principal representing the database login.
 */
public final class DatabaseLoginPrincipal implements Principal {

    /**
     * The string for this principal.
     */

    private static final String PRINCIPAL_STRING_VALUE = "DatabaseLogin";

    /**
     * The hash code for this principal.
     */

    private static final int HASH_CODE = PRINCIPAL_STRING_VALUE.hashCode();

    /**
     * The singleton instance of this object.
     */

    private static DatabaseLoginPrincipal singletonInstance = null;

    /**
     * Get the name for the principal.
     *
     * @return The fixed value representing a database login.
     */
    public String getName() {
        return PRINCIPAL_STRING_VALUE;
    }

    /**
     * Equals method. As all DatabaseLoginPrincipals are equal we only need to
     * check the other object is a DatabaseLoginPrincipal.
     *
     * @param otherObj
     *            The other object to compare to.
     *
     * @return true if hte objects are equal, false if not.
     */

    public boolean equals(final Object otherObj) {
        return (otherObj instanceof DatabaseLoginPrincipal);
    }

    /**
     * Return the hash code for this principal.
     *
     * @return The hash code for the principal.
     */

    public int hashCode() {
        return HASH_CODE;
    }

    /**
     * The toString method should just show the principal name.
     *
     * @return The name of this principal.
     */

    public String toString() {
        return getName();
    }

    /**
     * Singleton initialiser.
     */

    private static synchronized void initialise() {
        if (singletonInstance != null) {
            return;
        }

        singletonInstance = new DatabaseLoginPrincipal();
    }

    /**
     * Singleton accessor.
     *
     * @return The singleton instance of this principal.
     */

    public static DatabaseLoginPrincipal getInstance() {
        if (singletonInstance == null) {
            initialise();
        }

        return singletonInstance;
    }
}
