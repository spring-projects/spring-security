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

package org.acegisecurity;

import org.acegisecurity.acl.AclEntry;
import org.acegisecurity.acl.AclManager;


/**
 * Returns the indicated collection of <code>AclEntry</code>s when the given <code>Authentication</code> principal
 * is presented for the indicated domain <code>Object</code> instance.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class MockAclManager implements AclManager {
    //~ Instance fields ================================================================================================

    private Object object;
    private Object principal;
    private AclEntry[] acls;

    //~ Constructors ===================================================================================================

    public MockAclManager(Object domainObject, Object principal, AclEntry[] acls) {
        this.object = domainObject;
        this.principal = principal;
        this.acls = acls;
    }

    private MockAclManager() {}

    //~ Methods ========================================================================================================

    public AclEntry[] getAcls(Object domainInstance, Authentication authentication) {
        if (domainInstance.equals(object) && authentication.getPrincipal().equals(principal)) {
            return acls;
        } else {
            return null;
        }
    }

    public AclEntry[] getAcls(Object domainInstance) {
        if (domainInstance.equals(object)) {
            return acls;
        } else {
            return null;
        }
    }
}
