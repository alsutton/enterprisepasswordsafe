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

package com.enterprisepasswordsafe.database.abstraction.vendorspecific;

import com.enterprisepasswordsafe.database.abstraction.vendorspecific.implementations.GenericDAL;

import java.lang.reflect.InvocationTargetException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Class handling the mapping of database types to implementations.
 */

public class DALFactory
{
	public static DALInterface getDAL( final String databaseType )
			throws InstantiationException,
			IllegalAccessException, NoSuchMethodException, InvocationTargetException {
		Class<? extends DALInterface> dalClass = getDALClass(databaseType);
		Logger.getAnonymousLogger().log(Level.INFO, "Using DAL "+dalClass.getName());
		return dalClass.getDeclaredConstructor().newInstance();
	}

	private static Class<? extends DALInterface> getDALClass(final String databaseType) {
		String lookupName = databaseType.toLowerCase();
		for(SupportedDatabase database : SupportedDatabase.values()) {
			if(lookupName.equals(database.getType().toLowerCase())) {
				return database.getDALClass();
			}
		}

		return GenericDAL.class;
	}
}
