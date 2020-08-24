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
 * A security identity recognised by the ACL system.
 *
 * <p>
 * This interface provides indirection between actual security objects (eg principals,
 * roles, groups etc) and what is stored inside an <code>Acl</code>. This is because an
 * <code>Acl</code> will not store an entire security object, but only an abstraction of
 * it. This interface therefore provides a simple way to compare these abstracted security
 * identities with other security identities and actual security objects.
 * </p>
 *
 * @author Ben Alex
 */
public interface Sid extends Serializable {

	/**
	 * Refer to the <code>java.lang.Object</code> documentation for the interface
	 * contract.
	 * @param obj to be compared
	 * @return <code>true</code> if the objects are equal, <code>false</code> otherwise
	 */
	@Override
	boolean equals(Object obj);

	/**
	 * Refer to the <code>java.lang.Object</code> documentation for the interface
	 * contract.
	 * @return a hash code representation of this object
	 */
	@Override
	int hashCode();

}
