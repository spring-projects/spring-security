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

import org.springframework.security.Authentication;

import org.springframework.security.acl.AclEntry;


/**
 * Determines the ACLs that are effective for a given
 * <code>Authentication</code> object.
 *
 * <P>
 * Implementations will vary depending on their ability to interpret the
 * "recipient" object types contained in {@link BasicAclEntry} instances, and
 * how those recipient object types correspond to
 * <code>Authentication</code>-presented principals and granted authorities.
 * </p>
 *
 * <P>
 * Implementations should not filter the resulting ACL list from lower-order
 * permissions. So if a resulting ACL list grants a "read" permission, an
 * "unlimited" permission and a "zero" permission (due to the effective ACLs
 * for different granted authorities held by the <code>Authentication</code>
 * object), all three permissions would be returned as distinct
 * <code>BasicAclEntry</code> instances. It is the responsibility of the
 * relying classes (voters and business methods) to ignore or handle
 * lower-order permissions in a business logic dependent manner.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface EffectiveAclsResolver {
    //~ Methods ========================================================================================================

    /**
     * Determines the ACLs that apply to the presented <code>Authentication</code> object.
     *
     * @param allAcls every ACL assigned to a domain object instance
     * @param filteredBy the principal (populated with <code>GrantedAuthority</code>s along with any other members that
     *        relate to role or group membership) that effective ACLs should be returned for
     *
     * @return the ACLs that apply to the presented principal, or <code>null</code> if there are none after filtering
     */
    AclEntry[] resolveEffectiveAcls(AclEntry[] allAcls, Authentication filteredBy);
}
