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

package org.acegisecurity.acls;

import org.acegisecurity.acls.sid.Sid;

import java.io.Serializable;


/**
 * Represents an individual permission assignment within an {@link Acl}. 
 * 
 * <p>
 * Instances MUST be immutable, as they are returned by <code>Acl</code>
 * and should not allow client modification.
 * 
 * @author Ben Alex
 * @version $Id$
 *
 */
public interface AccessControlEntry {
    //~ Methods ========================================================================================================

    public Acl getAcl();

    /**
     * Obtains an identifier that represents this ACE.
     *
     * @return the identifier, or <code>null</code> if unsaved
     */
    public Serializable getId();

    public Permission getPermission();

    public Sid getSid();

    public boolean isGranting();
}
