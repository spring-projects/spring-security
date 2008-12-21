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
package org.springframework.security.acls.jdbc;

import org.springframework.security.acls.Acl;
import org.springframework.security.acls.NotFoundException;
import org.springframework.security.acls.objectidentity.ObjectIdentity;
import org.springframework.security.acls.sid.Sid;

import java.util.List;
import java.util.Map;


/**
 * Performs lookups for {@link org.springframework.security.acls.AclService}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface LookupStrategy {
    //~ Methods ========================================================================================================

    /**
     * Perform database-specific optimized lookup.
     *
     * @param objects the identities to lookup (required)
     * @param sids the SIDs for which identities are required (may be <tt>null</tt> - implementations may elect not
     *        to provide SID optimisations)
     *
     * @return a <tt>Map</tt> where keys represent the {@link ObjectIdentity} of the located {@link Acl} and values
     *         are the located {@link Acl} (never <tt>null</tt> although some entries may be missing; this method
     *         should not throw {@link NotFoundException}, as a chain of {@link LookupStrategy}s may be used
     *         to automatically create entries if required)
     */
    Map<ObjectIdentity, Acl> readAclsById(List<ObjectIdentity> objects, List<Sid> sids);
}
