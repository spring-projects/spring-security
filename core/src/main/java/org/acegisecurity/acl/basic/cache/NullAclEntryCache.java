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

package org.acegisecurity.acl.basic.cache;

import org.acegisecurity.acl.basic.AclObjectIdentity;
import org.acegisecurity.acl.basic.BasicAclEntry;
import org.acegisecurity.acl.basic.BasicAclEntryCache;


/**
 * Does not perform any caching.
 * 
 * <P>
 * <B>Do not use in production settings</B>, as ACL queries are likely to be
 * extensive.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class NullAclEntryCache implements BasicAclEntryCache {
    //~ Methods ================================================================

    /**
     * As nothing ever stored in the cache, will always return
     * <code>null</code>.
     *
     * @param aclObjectIdentity ignored
     *
     * @return always <code>null</code>
     */
    public BasicAclEntry[] getEntriesFromCache(
        AclObjectIdentity aclObjectIdentity) {
        return null;
    }

    /**
     * Meets method signature but doesn't store in any cache.
     *
     * @param basicAclEntry ignored
     */
    public void putEntriesInCache(BasicAclEntry[] basicAclEntry) {}
}
