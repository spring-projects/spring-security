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

package org.springframework.security.core.userdetails.memory;

import java.util.ArrayList;
import java.util.List;
import java.util.Vector;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;


/**
 * Used by {@link InMemoryDaoImpl} to temporarily store the attributes associated with a user.
 *
 * @author Ben Alex
 */
public class UserAttribute {
    //~ Instance fields ================================================================================================

    private List<GrantedAuthority> authorities = new Vector<GrantedAuthority>();
    private String password;
    private boolean enabled = true;

    //~ Methods ========================================================================================================

    public void addAuthority(GrantedAuthority newAuthority) {
        this.authorities.add(newAuthority);
    }

    public List<GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    /**
     * Set all authorities for this user.
     *
     * @param authorities {@link List} &lt;{@link GrantedAuthority}>
     * @since 1.1
     */
    public void setAuthorities(List<GrantedAuthority> authorities) {
        this.authorities = authorities;
    }

    /**
     * Set all authorities for this user from String values.
     * It will create the necessary {@link GrantedAuthority} objects.
     *
     * @param authoritiesAsStrings {@link List} &lt;{@link String}>
     * @since 1.1
     */
    public void setAuthoritiesAsString(List<String> authoritiesAsStrings) {
        setAuthorities(new ArrayList<GrantedAuthority>(authoritiesAsStrings.size()));
        for(String authority : authoritiesAsStrings) {
            addAuthority(new SimpleGrantedAuthority(authority));
        }
    }

    public String getPassword() {
        return password;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public boolean isValid() {
        if ((this.password != null) && (authorities.size() > 0)) {
            return true;
        } else {
            return false;
        }
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
