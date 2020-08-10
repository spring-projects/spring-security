/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.acls.model;

import java.io.Serializable;

/**
 * A mutable <tt>Acl</tt>.
 * <p>
 * A mutable ACL must ensure that appropriate security checks are performed before
 * allowing access to its methods.
 *
 * @author Ben Alex
 */
public interface MutableAcl extends Acl {

	// ~ Methods
	// ========================================================================================================

	void deleteAce(int aceIndex) throws NotFoundException;

	/**
	 * Obtains an identifier that represents this <tt>MutableAcl</tt>.
	 * @return the identifier, or <tt>null</tt> if unsaved
	 */
	Serializable getId();

	void insertAce(int atIndexLocation, Permission permission, Sid sid, boolean granting) throws NotFoundException;

	/**
	 * Changes the present owner to a different owner.
	 * @param newOwner the new owner (mandatory; cannot be null)
	 */
	void setOwner(Sid newOwner);

	/**
	 * Change the value returned by {@link Acl#isEntriesInheriting()}.
	 * @param entriesInheriting the new value
	 */
	void setEntriesInheriting(boolean entriesInheriting);

	/**
	 * Changes the parent of this ACL.
	 * @param newParent the new parent
	 */
	void setParent(Acl newParent);

	void updateAce(int aceIndex, Permission permission) throws NotFoundException;

}
