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

package org.acegisecurity.acl;

import org.acegisecurity.Authentication;


/**
 * Obtains the <code>AclEntry</code> instances that apply to a particular
 * domain object instance.
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface AclManager {
    //~ Methods ================================================================

    /**
     * Obtains the ACLs that apply to the specified domain instance.
     *
     * @param domainInstance the instance for which ACL information is required
     *        (never <code>null</code>)
     *
     * @return the ACLs that apply, or <code>null</code> if no ACLs apply to
     *         the specified domain instance
     */
    public AclEntry[] getAcls(Object domainInstance);

    /**
     * Obtains the ACLs that apply to the specified domain instance, but only
     * including those ACLs which have been granted to the presented
     * <code>Authentication</code> object
     *
     * @param domainInstance the instance for which ACL information is required
     *        (never <code>null</code>)
     * @param authentication the prncipal for which ACL information should be
     *        filtered (never <code>null</code>)
     *
     * @return only those ACLs applying to the domain instance that have been
     *         granted to the principal (or <code>null</code>) if no such ACLs
     *         are found
     */
    public AclEntry[] getAcls(Object domainInstance,
        Authentication authentication);
}
