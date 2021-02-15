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

package com.enterprisepasswordsafe.model;

/**
 * Summary of an entity which has some access control rights
 */
public class AccessSummary
	implements Comparable<AccessSummary> {
	
	private final EntityWithName entityWithName;
	private final boolean canRead;
	private final boolean canModify;
	private final boolean canApproveRARequests;
	private final boolean canViewHistory;
	
	/**
	 * Constructor stores values.
	 */
	
	public AccessSummary(final EntityWithName entityWithName,
			final boolean canRead, final boolean canModify,
			final boolean canApproveRARequests,
			final boolean canViewHistory) {
		this.entityWithName = entityWithName;
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

	public Long getId() {
		return entityWithName.getId();
	}
	
	/**
	 * Get the name of the group.
	 * 
	 * @return The name of the group this is a summary for.
	 */

	public String getName() {
		return entityWithName.getName();
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
		return entityWithName.getName().compareToIgnoreCase(otherSummary.getName());
	}
	
	/**
	 * Equality test method.
	 */
	@Override
	public boolean equals( final Object otherObject ) {
		if(!(otherObject instanceof AccessSummary)) {
			return false;
		}
		return entityWithName.getId().equals(((AccessSummary)otherObject).getId());
	}
	
	/**
	 * Hashcode method
	 */
	@Override
	public int hashCode() {
		return entityWithName.getId().hashCode();
	}
}
