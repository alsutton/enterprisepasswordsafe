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

package com.enterprisepasswordsafe.engine.database.derived;

import java.util.HashSet;
import java.util.Set;

import com.enterprisepasswordsafe.engine.database.Password;
import com.enterprisepasswordsafe.proguard.JavaBean;

/**
 * Class holding the lists of expired and expiring passwords.
 */
public class ExpiringAccessiblePasswords implements JavaBean {
    /**
     * The list of expiring passwords (i.e. those in the warning period).
     */

    private Set<Password> expiring;

    /**
     * The List of expired passwords.
     */

    private Set<Password> expired;

    /**
     * Constructor. Initialises lists.
     */

    protected ExpiringAccessiblePasswords() {
        expiring = new HashSet<Password>();
        expired = new HashSet<Password>();
    }

    /**
     * Get the Set of expiring passwords.
     *
     * @return The expiring passwords.
     */

    public final Set<Password> getExpiring() {
        return expiring;
    }

    /**
     * Get the Set of expired passwords.
     *
     * @return The expired passwords.
     */

    public final Set<Password> getExpired() {
        return expired;
    }
}
