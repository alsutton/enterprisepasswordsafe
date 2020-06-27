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

package com.enterprisepasswordsafe.engine.database;

import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Base class for all access roles for restricted access items.
 */

public abstract class AccessRole {
	/**
	 * The requestor-only role
	 */
	
	public static final String REQUESTER_ROLE = "R";
	
	/**
	 * The approver/requestor role
	 */
	
	public static final String APPROVER_ROLE = "A";
	
	/**
	 * The history viewer role
	 */
	
	public static final String HISTORYVIEWER_ROLE = "H";
	
	/**
	 * The approver/requestor role as a character
	 */
	
	public static final char APPROVER_ROLE_CHAR = 'A';
	
	/**
	 * The item involved in this role.
	 */
	
	private String itemId;
	
	/**
	 * The actor involved in this role.
	 */
	
	private String actorId;
	
	/**
	 * The role.
	 */
	
	private String role;

	/**
	 * Constructor, stores information.
	 * 
	 * @param theItemId The ID of the item involved in this role
	 * @param theActorId The ID of the actor involved in this role.
	 * @param theRole The role.
	 */
	
	protected AccessRole(final String theItemId, final String theActorId, 
			final String theRole) {
		itemId = theItemId;
		actorId = theActorId;
		role = theRole;
	}
	
	/**
	 * Costructor, extracts information from a result set.
	 */
	
	protected AccessRole(final ResultSet rs, final int startIdx) 
		throws SQLException {
		int currentIdx = startIdx;
		itemId = rs.getString(currentIdx++);
		actorId = rs.getString(currentIdx++);
		role = rs.getString(currentIdx);
	}
	
	/**
	 * Get the ID of the actor involved in this role.
	 * 
	 * @return The ID of the actor involved in this role.
	 */
	
	public String getActorId() {
		return actorId;
	}

	/**
	 * Set the ID of the actor involved in this role.
	 * 
	 * @param actorId The ID of the actor involved in this role
	 */
	public void setActorId(String actorId) {
		this.actorId = actorId;
	}

	/**
	 * Get the ID of the item involved in this role.
	 * 
	 * @return The ID of the item involved in the role.
	 */
	public String getItemId() {
		return itemId;
	}

	/**
	 * Set the ID of the item involved in this role.
	 * 
	 * @param itemId The ID of the item involved in this role.
	 */
	public void setItemId(String itemId) {
		this.itemId = itemId;
	}

	/**
	 * Get the role.
	 * 
	 * @return The role.
	 */
	public String getRole() {
		return role;
	}

	/**
	 * Set the role.
	 * 
	 * @param role The role.
	 */
	public void setRole(String role) {
		this.role = role;
	}	

	/**
	 * Summary for an approver. 
	 */

	public static class ApproverSummary
		implements Comparable<ApproverSummary> {
		/**
		 * The ID of the approver.
		 */
		
		private String id;
		
		/**
		 * The Email address of the approver.
		 */
		
		private String email;
		
		/**
		 * Constructor. Stores the data.
		 * 
		 * @param theId The ID of the approver.
		 * @param theEmail The Email address of the approver.
		 */
		
		public ApproverSummary(final String theId, final String theEmail) {
			id = theId;
			email = theEmail;
		}
		
		/**
		 * Get the ID of the approver.
		 * 
		 * @return The User ID of approver.
		 */
		
		public String getId() {
			return id;
		}
		
		/**
		 * Get th Email address of the approver.
		 * 
		 * @return The Email address of the approver. 
		 */
		
		public String getEmail() {
			return email;
		}

		/**
		 * Compares this object to another.
		 * 
		 * @param otherObject The object to compare to.
		 * 
		 * @return a comparison of the user IDs, or Integer.MIN_VALUE if the 
		 * 	comparing object is not of the same type.
		 */
		public int compareTo(ApproverSummary otherObject) {
            if(otherObject == null) {
                return Integer.MAX_VALUE;
            }
			return id.compareTo(otherObject.id);
		}				
		
		/**
		 * Test for the equality of two objects.
		 * 
		 * @param otherObject The other object to compare to.
		 * 
		 * @return true if they are equal, false if not.
		 */
		
		public boolean equals(Object otherObject) {
			if( !(otherObject instanceof ApproverSummary) ) {
				return false;
			}
			
			ApproverSummary otherSummary = (ApproverSummary) otherObject;
			return id.equals(otherSummary.id);
		}
		
		/**
		 * Get a HashCode for this summary. This is the same as the hash code 
		 * for the ID.
		 * 
		 * @return A hash code for this summary.
		 */
		
		public int hashCode() {
			return id.hashCode();
		}
	}
}
