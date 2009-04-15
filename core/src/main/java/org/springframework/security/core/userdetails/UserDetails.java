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

package org.springframework.security.core.userdetails;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.io.Serializable;
import java.util.List;


/**
 * Provides core user information.
 *
 * <p>
 * Implementations are not used directly by Spring Security for security
 * purposes. They simply store user information which is later encapsulated
 * into {@link Authentication} objects. This allows non-security related user
 * information (such as email addresses, telephone numbers etc) to be stored
 * in a convenient location.
 * </p>
 *
 * <p>
 * Concrete implementations must take particular care to ensure the non-null
 * contract detailed for each method is enforced. See
 * {@link org.springframework.security.core.userdetails.User} for a
 * reference implementation (which you might like to extend).
 * </p>
 *
 * <p>
 * Concrete implementations should be immutable (value object semantics,
 * like a String). This is because the <code>UserDetails</code> will be
 * stored in caches and as such multiple threads may use the same instance.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface UserDetails extends Serializable {
    //~ Methods ========================================================================================================

    /**
     * Returns the authorities granted to the user. Cannot return <code>null</code>.
     *
     * @return the authorities, sorted by natural key (never <code>null</code>)
     */
    List<GrantedAuthority> getAuthorities();

    /**
     * Returns the password used to authenticate the user. Cannot return <code>null</code>.
     *
     * @return the password (never <code>null</code>)
     */
    String getPassword();

    /**
     * Returns the username used to authenticate the user. Cannot return <code>null</code>.
     *
     * @return the username (never <code>null</code>)
     */
    String getUsername();

    /**
     * Indicates whether the user's account has expired. An expired account cannot be authenticated.
     *
     * @return <code>true</code> if the user's account is valid (ie non-expired), <code>false</code> if no longer valid
     *         (ie expired)
     */
    boolean isAccountNonExpired();

    /**
     * Indicates whether the user is locked or unlocked. A locked user cannot be authenticated.
     *
     * @return <code>true</code> if the user is not locked, <code>false</code> otherwise
     */
    boolean isAccountNonLocked();

    /**
     * Indicates whether the user's credentials (password) has expired. Expired credentials prevent
     * authentication.
     *
     * @return <code>true</code> if the user's credentials are valid (ie non-expired), <code>false</code> if no longer
     *         valid (ie expired)
     */
    boolean isCredentialsNonExpired();

    /**
     * Indicates whether the user is enabled or disabled. A disabled user cannot be authenticated.
     *
     * @return <code>true</code> if the user is enabled, <code>false</code> otherwise
     */
    boolean isEnabled();
}
