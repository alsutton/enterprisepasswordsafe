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

import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.Iterator;
import java.util.List;

/**
 * Data access object for hierarchy node access rules.
 */

public class HierarchyNodeAccessRuleDAOGroupPrecedent
	extends HierarchyNodeAccessRuleDAO {

    @Override
	public byte getAccessibilityForUser( final String nodeId, final User user, boolean recurse)
        throws SQLException, GeneralSecurityException {
    	if(nodeId == null || nodeId.equals(HierarchyNode.ROOT_NODE_ID)) {
    		return ACCESIBILITY_ALLOWED;
    	}

	    boolean allowed = false;
    	List<byte[]> rules = getUsersGroupAccessibilityRules(nodeId, user);
    	Iterator<byte[]> ruleIter = rules.iterator();
    	while( ruleIter.hasNext() ) {
    		byte[] ruleValue = ruleIter.next();
    		if			( ruleValue[0] == ACCESIBILITY_DENIED ) {
    			return ACCESIBILITY_DENIED;
    		} else if 	( ruleValue[0] == ACCESIBILITY_ALLOWED ) {
    			allowed = true;
    		}
    	}

		if( allowed ) {
	    	if( recurse ) {
	    		return getAccessibilityForUser(HierarchyNodeDAO.getInstance().getParentIdById(nodeId), user);
	    	}

	    	return ACCESIBILITY_ALLOWED;
		}

    	byte[] rule = getUserAccessibilityRule(nodeId, user);
	    if( rule != null ) {
	    	byte decodedRule;
	    	if( rule.length > 1 ) {
	    		decodedRule = user.getKeyDecrypter().decrypt( rule )[0];
	    	} else {
	    		decodedRule = rule[0];
	    	}
			return decodedRule;
	    }

        String defaultRule = ConfigurationDAO.getValue(ConfigurationOption.DEFAULT_HIERARCHY_ACCESS_RULE);
	    if( defaultRule != null && defaultRule.equals("D") ) {
	        return ACCESIBILITY_DENIED;
	    }

    	return ACCESIBILITY_ALLOWED;
    }
}