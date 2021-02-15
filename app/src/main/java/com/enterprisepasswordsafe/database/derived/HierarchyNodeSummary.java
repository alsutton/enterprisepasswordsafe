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

/**
 * A class holding the summary of a node.
 */
@Value.Immutable
public interface HierarchyNodeSummary extends Comparable<HierarchyNodeSummary> {
	String id();
	String parentage();

	/**
	 * Compare this summary to another object. The comparison is made on the
	 * parentage of the node.
	 *
	 * @param otherSummary The HierarchyNodeSummary to compare this object to.
	 *
	 * @return The result of the parentage comparison.
	 */
	@Override
	default int compareTo(HierarchyNodeSummary otherSummary) {
		return parentage().compareTo(otherSummary.parentage());
	}
}
