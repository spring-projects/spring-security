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

package org.springframework.security.acls.domain;

import org.springframework.security.acls.model.Acl;


/**
 * Strategy used by {@link AclImpl} to determine whether a principal is permitted to call
 * adminstrative methods on the <code>AclImpl</code>.
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface AclAuthorizationStrategy {
    //~ Static fields/initializers =====================================================================================

    int CHANGE_OWNERSHIP = 0;
    int CHANGE_AUDITING = 1;
    int CHANGE_GENERAL = 2;

    //~ Methods ========================================================================================================

    void securityCheck(Acl acl, int changeType);
}
