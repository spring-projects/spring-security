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

import java.io.Serializable;


/**
 * Basic concrete implementation of a {@link GrantedAuthority}.<p>Stores a <code>String</code> representation of an
 * authority granted to  the {@link Authentication} object.</p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class GrantedAuthorityImpl implements GrantedAuthority, Serializable {
    //~ Instance fields ================================================================================================

	private static final long serialVersionUID = 1L;
    private String role;

    //~ Constructors ===================================================================================================

    public GrantedAuthorityImpl(String role) {
        super();
        this.role = role;
    }

    //~ Methods ========================================================================================================

    public boolean equals(Object obj) {
        if (obj instanceof String) {
            return obj.equals(this.role);
        }

        if (obj instanceof GrantedAuthority) {
            GrantedAuthority attr = (GrantedAuthority) obj;

            return this.role.equals(attr.getAuthority());
        }

        return false;
    }

    public String getAuthority() {
        return this.role;
    }

    public int hashCode() {
        return this.role.hashCode();
    }

    public String toString() {
        return this.role;
    }
}
