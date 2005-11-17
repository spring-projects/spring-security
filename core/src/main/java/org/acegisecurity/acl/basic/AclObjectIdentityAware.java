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
 * Indicates a domain object instance is able to provide {@link
 * AclObjectIdentity} information.
 * 
 * <P>
 * Domain objects must implement this interface if they wish to provide an
 * <code>AclObjectIdentity</code> rather than it being determined by relying
 * classes. Specifically, the {@link BasicAclProvider} detects and uses this
 * interface.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface AclObjectIdentityAware {
    //~ Methods ================================================================

    /**
     * Retrieves the <code>AclObjectIdentity</code> for this instance.
     *
     * @return the ACL object identity for this instance (can never be
     *         <code>null</code>)
     */
    public AclObjectIdentity getAclObjectIdentity();
}
