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

package com.enterprisepasswordsafe.database.derived;

import org.immutables.value.Value;

@Value.Immutable
public interface IntegrationModuleScriptSummary extends Comparable<IntegrationModuleScriptSummary> {
	String getModuleId();
	String getScriptId();
	@Value.Auxiliary
	String getModuleName();
	@Value.Auxiliary
	boolean isActive();
	@Value.Auxiliary
	String getName();

	@Override
	default int compareTo(IntegrationModuleScriptSummary otherSummary) {
		if(!otherSummary.getName().equals(getName())) {
			return getName().compareTo(otherSummary.getName());
		}
		
		if(!otherSummary.getScriptId().equals(getScriptId())) {
			return getScriptId().compareTo(otherSummary.getScriptId());
		}
		
		return 0;
	}
}
