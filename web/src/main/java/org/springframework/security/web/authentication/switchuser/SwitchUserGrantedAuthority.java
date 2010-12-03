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

package org.springframework.security.web.authentication.switchuser;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;


/**
 * Custom {@code GrantedAuthority} used by
 * {@link org.springframework.security.web.authentication.switchuser.SwitchUserFilter}
 * <p>
 * Stores the {@code Authentication} object of the original user to be used later when 'exiting' from a user switch.
 *
 * @author Mark St.Godard
 *
 * @see org.springframework.security.web.authentication.switchuser.SwitchUserFilter
 */
public final class SwitchUserGrantedAuthority implements GrantedAuthority {
    //~ Instance fields ================================================================================================
    private final String role;
    private final Authentication source;

    //~ Constructors ===================================================================================================

    public SwitchUserGrantedAuthority(String role, Authentication source) {
        this.role = role;
        this.source = source;
    }

    //~ Methods ========================================================================================================

    /**
     * Returns the original user associated with a successful user switch.
     *
     * @return The original <code>Authentication</code> object of the switched user.
     */
    public Authentication getSource() {
        return source;
    }

    public String getAuthority() {
        return role;
    }

    public int hashCode() {
        return 31 ^ source.hashCode() ^ role.hashCode();
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }

        if (obj instanceof SwitchUserGrantedAuthority) {
            SwitchUserGrantedAuthority swa = (SwitchUserGrantedAuthority) obj;
            return this.role.equals(swa.role) && this.source.equals(swa.source);
        }

        return false;
    }

    public String toString() {
        return "Switch User Authority [" + role + "," + source + "]" ;
    }
}
