/* Copyright 2004 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.sf.acegisecurity.providers.dao;

/**
 * Provides a cache of {@link User} objects.
 * 
 * <P>
 * Implementations should provide appropriate methods to set their cache
 * parameters (eg time-to-live) and/or force removal of entities before their
 * normal expiration. These are not part of the <code>UserCache</code>
 * interface contract because they vary depending on the type of caching
 * system used (eg in-memory vs disk vs cluster vs hybrid).
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface UserCache {
    //~ Methods ================================================================

    /**
     * Obtains a {@link User} from the cache.
     *
     * @param username the {@link User#getUsername()} used to place the user in
     *        the cache
     *
     * @return the populated <code>User</code> or <code>null</code> if the user
     *         could not be found or if the cache entry has expired
     */
    public User getUserFromCache(String username);

    /**
     * Places a {@link User} in the cache. The <code>username</code> is the key
     * used to subsequently retrieve the <code>User</code>.
     *
     * @param user the fully populated <code>User</code> to place in the cache
     */
    public void putUserInCache(User user);
}
