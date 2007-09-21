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

package org.springframework.security.acl.basic.cache;

import org.springframework.security.acl.basic.BasicAclEntry;

import org.springframework.util.Assert;

import java.io.Serializable;


/**
 * Used by {@link EhCacheBasedAclEntryCache} to store the array of <code>BasicAclEntry</code>s in the cache.<P>This
 * is necessary because caches store a single object per key, not an array.</p>
 *  <P>This class uses value object semantics. ie: construction-based initialisation without any setters for the
 * properties.</p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class BasicAclEntryHolder implements Serializable {
    //~ Instance fields ================================================================================================

    private BasicAclEntry[] basicAclEntries;

    //~ Constructors ===================================================================================================

/**
     * Constructs the <code>BasicAclEntryHolder</code>.
     *
     * @param aclEntries to cache (any <code>null</code>s will cause an
     *        exception, which should not be a problem as the contract for
     *        <code>BasicAclEntryCache</code> allows exceptions if
     *        <code>null</code>s are presented)
     *
     * @throws IllegalArgumentException if a <code>null</code> exists anywhere
     *         in the <code>aclEntries</code> or if a <code>null</code> is
     *         passed to the constructor
     */
    public BasicAclEntryHolder(BasicAclEntry[] aclEntries) {
        Assert.notNull(aclEntries, "aclEntries cannot be null");

        for (int i = 0; i < aclEntries.length; i++) {
            Assert.notNull(aclEntries[i], "aclEntries cannot be null");
        }

        this.basicAclEntries = aclEntries;
    }

    //~ Methods ========================================================================================================

    public BasicAclEntry[] getBasicAclEntries() {
        return basicAclEntries;
    }
}
