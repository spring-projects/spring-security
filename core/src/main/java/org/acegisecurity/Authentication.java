/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity;

import java.security.Principal;


/**
 * Represents an authentication request.
 * 
 * <p>
 * An <code>Authentication</code> object is not considered authenticated until
 * it is processed by an {@link AuthenticationManager}.
 * </p>
 * 
 * <p>
 * Stored in a request {@link net.sf.acegisecurity.context.SecureContext}.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface Authentication extends Principal {
    //~ Methods ================================================================

    public void setAuthenticated(boolean isAuthenticated);

    /**
     * Indicates whether or not authentication was attempted by the {@link
     * net.sf.acegisecurity.intercept.AbstractSecurityInterceptor}. Note that
     * classes should not rely on this value as being valid unless it has been
     * set by a trusted <code>AbstractSecurityInterceptor</code>.
     *
     * @return true if authenticated by the
     *         <code>AbstractSecurityInterceptor</code>
     */
    public boolean isAuthenticated();

    /**
     * Set by an <code>AuthenticationManager</code> to indicate the authorities
     * that the principal has been granted. Note that classes should not rely
     * on this value as being valid unless it has been set by a trusted
     * <code>AuthenticationManager</code>.
     *
     * @return the authorities granted to the principal, or <code>null</code>
     *         if authentication has not been completed
     */
    public GrantedAuthority[] getAuthorities();

    /**
     * The credentials that prove the principal is correct. This is usually a
     * password, but could be anything relevant to the
     * <code>AuthenticationManager</code>. Callers are expected to populate
     * the credentials.
     *
     * @return the credentials that prove the identity of the
     *         <code>Principal</code>
     */
    public Object getCredentials();

    /**
     * The identity of the principal being authenticated. This is usually a
     * username. Callers are expected to populate the principal.
     *
     * @return the <code>Principal</code> being authenticated
     */
    public Object getPrincipal();
}
