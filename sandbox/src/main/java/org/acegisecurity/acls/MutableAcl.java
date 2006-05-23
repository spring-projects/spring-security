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
 * A mutable <code>Acl</code>.
 * 
 * <p>
 * A mutable ACL must ensure that appropriate security checks are performed
 * before allowing access to its methods.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface MutableAcl extends Acl {
    //~ Methods ========================================================================================================

    public void deleteAce(Long aceId) throws NotFoundException;

    /**
     * Obtains an identifier that represents this <code>MutableAcl</code>.
     *
     * @return the identifier, or <code>null</code> if unsaved
     */
    public Serializable getId();

    public void insertAce(Long afterAceId, Permission permission, Sid sid, boolean granting)
        throws NotFoundException;

    public void setEntriesInheriting(boolean entriesInheriting);

    /**
     * Changes the parent of this ACL.
     *
     * @param newParent the new parent
     */
    public void setParent(MutableAcl newParent);

    public void updateAce(Long aceId, Permission permission)
        throws NotFoundException;
}
