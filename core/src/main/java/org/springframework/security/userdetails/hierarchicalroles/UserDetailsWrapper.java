/*
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

package org.springframework.security.userdetails.hierarchicalroles;

import org.springframework.security.GrantedAuthority;
import org.springframework.security.userdetails.UserDetails;

/**
 * This class wraps Acegi's UserDetails in a way that its getAuthorities()-Method is
 * delegated to RoleHierarchy.getReachableGrantedAuthorities. All other methods are
 * delegated to the UserDetails implementation.
 *
 * @author Michael Mayr
 */
public class UserDetailsWrapper implements UserDetails {

    private static final long serialVersionUID = 1532428778390085311L;

    private UserDetails userDetails = null;

    private RoleHierarchy roleHierarchy = null;

    public UserDetailsWrapper(UserDetails userDetails, RoleHierarchy roleHierarchy) {
        this.userDetails = userDetails;
        this.roleHierarchy = roleHierarchy;
    }

    public boolean isAccountNonExpired() {
        return userDetails.isAccountNonExpired();
    }

    public boolean isAccountNonLocked() {
        return userDetails.isAccountNonLocked();
    }

    public GrantedAuthority[] getAuthorities() {
        return roleHierarchy.getReachableGrantedAuthorities(userDetails.getAuthorities());
    }

    public boolean isCredentialsNonExpired() {
        return userDetails.isCredentialsNonExpired();
    }

    public boolean isEnabled() {
        return userDetails.isEnabled();
    }

    public String getPassword() {
        return userDetails.getPassword();
    }

    public String getUsername() {
        return userDetails.getUsername();
    }

    public UserDetails getUnwrappedUserDetails() {
        return userDetails;
    }

}