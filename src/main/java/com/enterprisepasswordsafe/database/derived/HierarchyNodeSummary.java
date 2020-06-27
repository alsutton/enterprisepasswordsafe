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

/**
 * A class holding the summary of a node.
 */

public class HierarchyNodeSummary
	implements Comparable<HierarchyNodeSummary> {

	/**
	 * The ID for the node.
	 */
	
	private final String id;
	
	/**
	 * The parentage text for the node
	 */
	
	private final String parentage;
	
	/**
	 * Constructor stores information
	 */
	
	public HierarchyNodeSummary( String theId, String theParentage ) {
		id = theId;
		parentage = theParentage;
	}

	public String getId() {
		return id;
	}

	public String getParentage() {
		return parentage;
	}
	
	/**
	 * Equality operator.
	 * 
	 * @param otherObject The other object to compare to.
	 */
	
	public boolean equals(Object otherObject) {
		if(!(otherObject instanceof HierarchyNodeSummary)) {
			return false;
		}
		
		HierarchyNodeSummary otherSummary = 
			(HierarchyNodeSummary) otherObject;
		return id.equals(otherSummary.id);
	}
	
	/**
	 * Generate the HashCode for this object. The ID is the unique identifier
	 * so we can use the HashCode from the ID.
	 */
	
	public int hashCode() {
		return id.hashCode();
	}

	/**
	 * Compare this summary to another object. The comparison is made on the 
	 * parentage of the node.
	 * 
	 * @param otherSummary The HierarchyNodeSummary to compare this object to.
	 * 
	 * @return The result of the parentage comparison.
	 */

    @Override
	public int compareTo(HierarchyNodeSummary otherSummary) {
		return parentage.compareTo(otherSummary.parentage);
	}
}
