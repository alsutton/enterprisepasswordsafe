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
 * A factory for access controlled objects.
 */

public interface AccessControledObjectDAO {

	/**
	 * Get the access controlled object by it's ID.
	 * 
	 * @param fetchingUser The user the object is being fetched for.
	 * @param id The ID of the object to fetch.
	 *
     */

	AccessControledObject getById(final User fetchingUser, final String id)
    ;

	/**
	 * Delete an access controlled object via its' ID
	 * 
	 * @param deletingUser The user deleting the object
	 * @param aco The object being deleted.
	 *
     */

	void delete(final User deletingUser, final AccessControledObject aco)
    ;
	
	/**
	 * Gets an access controlled object for a specific user. This method should apply
	 * any access checking required to ensure the user has access to the object.
	 */

	AccessControledObject getByIdForUser(final User theUser, final String id)
    ;
	
}
