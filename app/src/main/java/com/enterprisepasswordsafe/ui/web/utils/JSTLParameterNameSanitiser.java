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
 * Class responsible for ensuring that a parameter name passed to it gets converted to a JSTL friendly format
 */
public class JSTLParameterNameSanitiser {

	public static String santiseName(final String originalName) {
		StringBuilder endName = new StringBuilder(originalName.length());
		
		boolean capsNext = false;
		for(char c : originalName.toCharArray()) {
			switch(c) {
			case '.':
				endName.append('_');
				break;
			case '_':
				capsNext = true;
				break;
			default:
				if(capsNext) {
					endName.append(Character.toUpperCase(c));
					capsNext = false;
				} else {
					endName.append(c);
				}
				break;
			}
		}
		
		return endName.toString();
	}
}
