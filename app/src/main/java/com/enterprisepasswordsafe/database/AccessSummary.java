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
 * Summary of a group holding only it's group name and id.
 */
public class AccessSummary
	implements Comparable<AccessSummary> {
	
	/**
	 * The actor id.
	 */
	
	private final String id;
	
	/**
	 * The actor name.
	 */
	
	private final String name;

	/**
	 * Whether or not this actor can perform a read.
	 */
	
	private final boolean canRead;
	
	/**
	 * Whether or not this actor can perform a read.
	 */
	
	private final boolean canModify;
	
	/**
	 * Whether or not this actor can approve restricted access requests.
	 */
	
	private final boolean canApproveRARequests;
	
	/**
	 * Whether or not this actor can approve restricted access requests.
	 */
	
	private final boolean canViewHistory;
	
	/**
	 * Constructor stores values.
	 */
	
	public AccessSummary(final String id, final String name,
			final boolean canRead, final boolean canModify,
			final boolean canApproveRARequests,
			final boolean canViewHistory) {
		this.id						= id;
		this.name					= name;
		this.canRead				= canRead;
		this.canModify				= canModify;
		this.canApproveRARequests	= canApproveRARequests;
		this.canViewHistory			= canViewHistory; 
	}
	
	/**
	 * Get the ID for the group.
	 * 
	 * @return The ID of the group this is a summary for.
	 */

	public String getId() {
		return id;
	}
	
	/**
	 * Get the name of the group.
	 * 
	 * @return The name of the group this is a summary for.
	 */

	public String getName() {
		return name;
	}
	
	/**
	 * Return whether or not the group can perform a read operation.
	 * 
	 * @return true if the group can read, false if not.
	 */
	public boolean isReadable() {
		return canRead;
	}

	/**
	 * Return whether or not the group can perform a modify operation.
	 * 
	 * @return true if the group can modified, false if not.
	 */
	public boolean isModifiable() {
		return canModify;
	}
	
	/**
	 * Return whether or not the actor can approve RA requests.
	 * 
	 * @return true if the actor can approve RA requests, false if not.
	 */
	public boolean isRestrictedAccessApprover() {
		return canApproveRARequests;
	}
	
	/**
	 * Return whether or not the actor can approve RA requests.
	 * 
	 * @return true if the actor can approve RA requests, false if not.
	 */
	public boolean isHistoryViewer() {
		return this.canViewHistory;
	}
	
	/**
	 * Comparison method, used to sort entries by name.
	 * 
	 * @return The comparison of the actor name.
	 */
	@Override
	public int compareTo( final AccessSummary otherSummary ) {		
		return name.compareToIgnoreCase(otherSummary.name);
	}
	
	/**
	 * Equality test method.
	 */
	@Override
	public boolean equals( final Object otherObject ) {
		if(!(otherObject instanceof AccessSummary)) {
			return false;
		}
		return id.equals(((AccessSummary)otherObject).id);
	}
	
	/**
	 * Hashcode method
	 */
	@Override
	public int hashCode() {
		return id.hashCode();
	}
}
