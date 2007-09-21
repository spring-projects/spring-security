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

import org.springframework.security.acls.objectidentity.ObjectIdentity;
import org.springframework.security.acls.sid.Sid;

import java.util.Map;


/**
 * Performs optimised lookups for {@link JdbcAclService}.
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
     * @param sids the SIDs for which identities are required (may be <code>null</code> - implementations may elect not
     *        to provide SID optimisations)
     *
     * @return the <code>Map</code> pursuant to the interface contract for {@link
     *         org.springframework.security.acls.AclService#readAclsById(ObjectIdentity[], Sid[])}
     */
    Map readAclsById(ObjectIdentity[] objects, Sid[] sids);
}
