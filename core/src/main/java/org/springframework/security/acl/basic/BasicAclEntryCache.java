/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.acl.basic;

/**
 * Provides a cache of {@link BasicAclEntry} objects.
 *
 * <P>
 * Implementations should provide appropriate methods to set their cache
 * parameters (eg time-to-live) and/or force removal of entities before their
 * normal expiration. These are not part of the
 * <code>BasicAclEntryCache</code> interface contract because they vary
 * depending on the type of caching system used (eg in-memory vs disk vs
 * cluster vs hybrid).
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 * @deprecated Use new spring-security-acl module instead
 */
public interface BasicAclEntryCache {
    //~ Methods ========================================================================================================

    /**
     * Obtains an array of {@link BasicAclEntry}s from the cache.
     *
     * @param aclObjectIdentity which should be obtained from the cache
     *
     * @return any applicable <code>BasicAclEntry</code>s (no <code>null</code>s are permitted in the returned array)
     *         or <code>null</code> if the object identity could not be found or if the cache entry has expired
     */
    BasicAclEntry[] getEntriesFromCache(AclObjectIdentity aclObjectIdentity);

    /**
     * Places an array of {@link BasicAclEntry}s in the cache.<P>No <code>null</code>s are allowed in the
     * passed array. If any <code>null</code> is passed, the implementation may throw an exception.</p>
     *
     * @param basicAclEntry the ACL entries to cache (the key will be extracted from the {@link
     *        BasicAclEntry#getAclObjectIdentity()} method
     */
    void putEntriesInCache(BasicAclEntry[] basicAclEntry);

    /**
     * Removes all ACL entries related to an {@link AclObjectIdentity} from the cache.
     *
     * @param aclObjectIdentity which should be removed from the cache
     */
    void removeEntriesFromCache(AclObjectIdentity aclObjectIdentity);
}
