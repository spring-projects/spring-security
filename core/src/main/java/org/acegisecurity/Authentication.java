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
 * Stored in a request {@link
 * org.acegisecurity.context.security.SecurityContext}.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface Authentication extends Principal, Serializable {
    //~ Methods ========================================================================================================

    /**
     * Set by an <code>AuthenticationManager</code> to indicate the authorities that the principal has been
     * granted. Note that classes should not rely on this value as being valid unless it has been set by a trusted
     * <code>AuthenticationManager</code>.<p>Implementations should ensure that modifications to the returned
     * array do not affect the state of the Authentication object (e.g. by returning an array copy).</p>
     *
     * @return the authorities granted to the principal, or <code>null</code> if authentication has not been completed
     */
    public GrantedAuthority[] getAuthorities();

    /**
     * The credentials that prove the principal is correct. This is usually a password, but could be anything
     * relevant to the <code>AuthenticationManager</code>. Callers are expected to populate the credentials.
     *
     * @return the credentials that prove the identity of the <code>Principal</code>
     */
    public Object getCredentials();

    /**
     * Stores additional details about the authentication request. These might be an IP address, certificate
     * serial number etc.
     *
     * @return additional details about the authentication request, or <code>null</code> if not used
     */
    public Object getDetails();

    /**
     * The identity of the principal being authenticated. This is usually a username. Callers are expected to
     * populate the principal.
     *
     * @return the <code>Principal</code> being authenticated
     */
    public Object getPrincipal();

    /**
     * Used to indicate to <code>AbstractSecurityInterceptor</code> whether it should present the
     * authentication token to the <code>AuthenticationManager</code>. Typically an <code>AuthenticationManager</code>
     * (or, more often, one of its <code>AuthenticationProvider</code>s) will return an immutable authentication token
     * after successful authentication, in which case that token can safely return <code>true</code> to this method.
     * Returning <code>true</code> will improve performance, as calling the <code>AuthenticationManager</code> for
     * every request will no longer be necessary.<p>For security reasons, implementations of this interface
     * should be very careful about returning <code>true</code> to this method unless they are either immutable, or
     * have some way of ensuring the properties have not been changed since original creation.</p>
     *
     * @return true if the token has been authenticated and the <code>AbstractSecurityInterceptor</code> does not need
     *         to represent the token for re-authentication to the <code>AuthenticationManager</code>
     */
    public boolean isAuthenticated();

    /**
     * See {@link #isAuthenticated()} for a full description.<p>Implementations should <b>always</b> allow this
     * method to be called with a <code>false</code> parameter, as this is used by various classes to specify the
     * authentication token should not be trusted. If an implementation wishes to reject an invocation with a
     * <code>true</code> parameter (which would indicate the authentication token is trusted - a potential security
     * risk) the implementation should throw an {@link IllegalArgumentException}.</p>
     *
     * @param isAuthenticated <code>true</code> if the token should be trusted (which may result in an exception) or
     *        <code>false</code> if the token should not be trusted
     *
     * @throws IllegalArgumentException if an attempt to make the authentication token trusted (by passing
     *         <code>true</code> as the argument) is rejected due to the implementation being immutable or
     *         implementing its own alternative approach to {@link #isAuthenticated()}
     */
    public void setAuthenticated(boolean isAuthenticated)
        throws IllegalArgumentException;
}
