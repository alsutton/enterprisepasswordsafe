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
 * An access rul for a hierarchy node.
 */

public class HierarchyNodeAccessRule
	implements Comparable<HierarchyNodeAccessRule> {
	/**
	 * The ID of the actor this rule is for.
	 */
	
	private final String actorId;
	
	/**
	 * The name of the actor this rule is for.
	 */
	
	private final String actorName;
	
	/**
	 * The rule.
	 */
	
	private final byte rule;
	
	/**
	 * Constructor, stores relevant values.
	 */
	
	public HierarchyNodeAccessRule( final String newActorId, 
			final String newActorName, final byte newRule ) {
		rule = newRule;
		actorId = newActorId;
		actorName = newActorName;
	}

	/**
	 * Get the rule for this summary.
	 * 
	 * @return The rule for this actor.
	 */
	public byte getRule() {
		return rule;
	}

	/**
	 * The ID of the actor this role is for,
	 * 
	 * @return The ID of the actor
	 */
	public String getActorId() {
		return actorId;
	}

	/**
	 * The name of the actor this role is for,
	 * 
	 * @return The name of the actor
	 */
	public String getActorName() {
		return actorName;
	}

	/**
	 * Compare with another hierarchy node access rule.
	 * 
	 * @param otherRule The other rule.
	 */
	@Override
	public int compareTo(HierarchyNodeAccessRule otherRule) {
		return actorName.compareToIgnoreCase(otherRule.actorName);
	}
}
