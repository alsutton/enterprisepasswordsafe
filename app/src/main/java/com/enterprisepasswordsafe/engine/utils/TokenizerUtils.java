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

package com.enterprisepasswordsafe.engine.utils;

import java.util.StringTokenizer;

/**
 * Utility class to help simplify actions the tokenizer.
 */

public final class TokenizerUtils {

    /**
     * The empty string.
     */

    private static final String EMPTY_STRING = "";

    /**
     * Private constructor. Prevents instanciation.
     */

    private TokenizerUtils() { }

    /**
     * Gets the next token, if the first token is the delimiter this indicates
     * it's an empty token.
     *
     * @param tokenizer
     *            The tokenizer to use.
     * @param delimiter
     *            The delimiter to check for.
     *
     * @return The next available, usable tag.
     */

    public static String getToken(final StringTokenizer tokenizer,
            final String delimiter) {
        if (!tokenizer.hasMoreTokens()) {
            return null;
        }

        String nextToken = tokenizer.nextToken();
        if (nextToken.equals(delimiter)) {
            return EMPTY_STRING;
        }

        if (!tokenizer.hasMoreTokens()) {
            return nextToken;
        }

        // Skip the next token which will be a delimiter.
        tokenizer.nextToken();

        return nextToken;
    }
}
