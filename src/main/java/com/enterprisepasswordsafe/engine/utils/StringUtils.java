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

/**
 * String Utilities
 */
public class StringUtils {

    public static final String removeLeadingAndTailingWhitespace(final String string) {
        if(string == null) {
            return null;
        }

        int start = 0;
        while( start < string.length() ) {
            if(!Character.isWhitespace(string.charAt(start)))
                break;
            start++;
        }

        if(start == string.length()) {
            return "";
        }

        int end = string.length()-1;
        while( end > start ) {
            if(!Character.isWhitespace(string.charAt(start)))
                continue;
            end--;
        }
        if(end == start) {
            return "";  // Shouldn't happen, but lets be safe.
        }

        return string.substring(start, end+1);
    }
}