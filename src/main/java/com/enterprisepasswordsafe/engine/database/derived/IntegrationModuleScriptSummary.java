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

package com.enterprisepasswordsafe.engine.database.derived;

public class IntegrationModuleScriptSummary
implements Comparable<IntegrationModuleScriptSummary> {
	/**
	 * The ID of the script.
	 */
	
	private String scriptId;
	
	/**
	 * The name of the script;
	 */
	
	private String name;
	
	/**
	 * The id of the integration module the script is configured for
	 */
	
	private String moduleId;
	
	/**
	 * The name of the integration module the script is configured for
	 */
	
	private String moduleName;
	
	/**
	 * Whether or not the script is active.
	 */
	
	private boolean isActive;
	
	/**
	 * Constructor. Stores the information passed to it.
	 */
	
	public IntegrationModuleScriptSummary(final String theScriptId, final String theName, 
			final String theModuleId, final String theModuleName, 
			final boolean newIsActive) {
		scriptId = theScriptId;
		name = theName;
		moduleId = theModuleId;
		moduleName = theModuleName;
		isActive = newIsActive;
	}

	public boolean isActive() {
		return isActive;
	}

	public String getModuleName() {
		return moduleName;
	}

	public String getName() {
		return name;
	}

	public String getScriptId() {
		return scriptId;
	}    	
	
	/**
	 * Get the hash code. Consists of the hash codes of the
	 * script name and script id.
	 */
	
	public int hashCode() {
		return scriptId.hashCode() | moduleId.hashCode();
	}
	
	/**
	 * Test for equality. We need only test the module and script
	 * ids for equality.
	 */
	
	public boolean equals(Object otherObject) {
		if( otherObject instanceof IntegrationModuleScriptSummary) {
			IntegrationModuleScriptSummary otherSummary = (IntegrationModuleScriptSummary) otherObject;
			
			return otherSummary.moduleId.equals(moduleId)
			&&	   otherSummary.scriptId.equals(scriptId);
		}
		
		return false;
	}

	/**
	 * Comparison test.
	 */
	
	public int compareTo(IntegrationModuleScriptSummary otherSummary) {
		if( otherSummary.name.equals(name) == false) {
			return name.compareTo(otherSummary.name);
		}
		
		if( otherSummary.scriptId.equals(scriptId) == false ) {
			return scriptId.compareTo(otherSummary.scriptId);
		}
		
		return 0;
	}
}
