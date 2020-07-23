/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.core.userdetails;

/**
 * Provides a cache of {@link UserDetails} objects.
 *
 * <p>
 * Implementations should provide appropriate methods to set their cache parameters (e.g.
 * time-to-live) and/or force removal of entities before their normal expiration. These
 * are not part of the <code>UserCache</code> interface contract because they vary
 * depending on the type of caching system used (in-memory, disk, cluster, hybrid etc.).
 * <p>
 * Caching is generally only required in applications which do not maintain server-side
 * state, such as remote clients or web services. The authentication credentials are then
 * presented on each invocation and the overhead of accessing a database or other
 * persistent storage mechanism to validate would be excessive. In this case, you would
 * configure a cache to store the <tt>UserDetails</tt> information rather than loading it
 * each time.
 *
 * @see org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider
 * @author Ben Alex
 */
public interface UserCache {

	/**
	 * Obtains a {@link UserDetails} from the cache.
	 * @param username the {@link User#getUsername()} used to place the user in the cache
	 * @return the populated <code>UserDetails</code> or <code>null</code> if the user
	 * could not be found or if the cache entry has expired
	 */
	UserDetails getUserFromCache(String username);

	/**
	 * Places a {@link UserDetails} in the cache. The <code>username</code> is the key
	 * used to subsequently retrieve the <code>UserDetails</code>.
	 * @param user the fully populated <code>UserDetails</code> to place in the cache
	 */
	void putUserInCache(UserDetails user);

	/**
	 * Removes the specified user from the cache. The <code>username</code> is the key
	 * used to remove the user. If the user is not found, the method should simply return
	 * (not thrown an exception).
	 * <p>
	 * Some cache implementations may not support eviction from the cache, in which case
	 * they should provide appropriate behaviour to alter the user in either its
	 * documentation, via an exception, or through a log message.
	 * @param username to be evicted from the cache
	 */
	void removeUserFromCache(String username);

}
