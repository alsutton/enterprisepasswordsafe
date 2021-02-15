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

/**
 * Generates IDs which are unique within this JVM.
 */
public final class IDGenerator {

    /**
     * The ID counter.
     */

    private static long idCounter = 0;

    /**
     * Private constructor to avoid instanciation.
     */

    private IDGenerator() { }

    /**
     * Generate a new, unique ID.
     *
     * @return The new unique ID.
     */
    public static synchronized String getID() {

        StringBuilder idBuffer = new StringBuilder();
        idBuffer.append(Long.toHexString(System.currentTimeMillis()));
        idBuffer.append(Long.toHexString(idCounter));
        String id = idBuffer.toString();

        idCounter++;
        if (idCounter == Long.MAX_VALUE) {
                idCounter = 0;
        }

        return id;
    }

}
