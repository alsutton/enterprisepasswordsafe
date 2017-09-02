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

package com.enterprisepasswordsafe.engine.utils;

import org.apache.commons.collections4.map.LRUMap;

/**
 * Type safe cache. Allows a maximum size to be specified.
 *
 * @author alsutton
 *
 * @param <K> The cache key type
 * @param <T> The cache object type
 */
public class Cache<K,T> {

	/**
	 * The default maximum size for the cache.
	 */
	private final static int DEFAULT_CACHE_SIZE = 1000;

	/**
	 * The LRUMap which backs the cache.
	 */
	private final LRUMap cacheMap;

	/**
	 * Constructor.
	 *
	 * @param size The maximum number of objects to be stored in the cache.
	 */

	public Cache(final int size) {
		cacheMap = new LRUMap(size);
	}

	/**
	 * Constructor. Uses the default size for the maximum number of objects to be held in the cache.
	 */
	public Cache() {
		this(DEFAULT_CACHE_SIZE);
	}

	/**
	 * Put an entry into the cache.
	 */

	public void put(K key, T object) {
		cacheMap.put(key, object);
	}

	/**
	 * Get an object from the cache
	 */

	@SuppressWarnings("unchecked")
	public T get(K key) {
		return (T) cacheMap.get(key);
	}

	/**
	 * Remove an object from the cache
	 */

	public void remove(K key) {
		cacheMap.remove(key);
	}
}
