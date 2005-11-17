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

package org.acegisecurity.acl.basic;

/**
 * Represents a data access object that can return the {@link BasicAclEntry}s
 * applying to a given ACL object identity.
 * 
 * <P>
 * <code>BasicAclDao</code> implementations are responsible for interpreting a
 * given {@link AclObjectIdentity} and being able to lookup and return the
 * corresponding {@link BasicAclEntry}[]s.
 * </p>
 * 
 * <P>
 * <code>BasicAclDao</code>s many, but are not required to, allow the backend
 * ACL repository to specify the class of <code>BasicAclEntry</code>
 * implementations that should be returned.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface BasicAclDao {
    //~ Methods ================================================================

    /**
     * Obtains the ACLs that apply to the specified domain instance.
     * 
     * <P>
     * Does <b>not</b> perform caching, include ACLs from any inheritance
     * hierarchy or filter returned objects based on effective permissions.
     * Implementations are solely responsible for returning ACLs found in the
     * ACL repository for the specified object identity.
     * </p>
     *
     * @param aclObjectIdentity the domain object instance that ACL information
     *        is being requested for (never <code>null</code>)
     *
     * @return the ACLs that apply (no <code>null</code>s are permitted in the
     *         array), or <code>null</code> if no ACLs could be found for the
     *         specified ACL object identity
     */
    public BasicAclEntry[] getAcls(AclObjectIdentity aclObjectIdentity);
}
