/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.ui.wrapper;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.UserDetails;
import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.context.SecureContext;

import java.security.Principal;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;


/**
 * An Acegi Security-aware <code>HttpServletRequestWrapper</code>, which uses
 * the <code>ContextHolder</code>-defined <code>Authentication</code> object
 * for {@link ContextHolderAwareRequestWrapper#isUserInRole(java.lang.String)}
 * and {@link javax.servlet.http.HttpServletRequestWrapper#getRemoteUser()}
 * responses.
 *
 * @author Orlando Garcia Carmona
 * @author Ben Alex
 * @version $Id$
 */
public class ContextHolderAwareRequestWrapper extends HttpServletRequestWrapper {
    //~ Constructors ===========================================================

    public ContextHolderAwareRequestWrapper(HttpServletRequest request) {
        super(request);
    }

    //~ Methods ================================================================

    /**
     * Returns the principal's name, as obtained from the
     * <code>ContextHolder</code>. Properly handles both
     * <code>String</code>-based and <code>UserDetails</code>-based
     * principals.
     *
     * @return the username or <code>null</code> if unavailable
     */
    public String getRemoteUser() {
        Authentication auth = getAuthentication();

        if ((auth == null) || (auth.getPrincipal() == null)) {
            return null;
        }

        if (auth.getPrincipal() instanceof UserDetails) {
            return ((UserDetails) auth.getPrincipal()).getUsername();
        }

        return auth.getPrincipal().toString();
    }

    /**
     * Simple searches for an exactly matching {@link
     * GrantedAuthority#getAuthority()}.
     * 
     * <p>
     * Will always return <code>false</code> if the <code>ContextHolder</code>
     * contains an <code>Authentication</code> with
     * <code>null</code><code>principal</code> and/or
     * <code>GrantedAuthority[]</code> objects.
     * </p>
     *
     * @param role the <code>GrantedAuthority</code><code>String</code>
     *        representation to check for
     *
     * @return <code>true</code> if an <b>exact</b> (case sensitive) matching
     *         granted authority is located, <code>false</code> otherwise
     */
    public boolean isUserInRole(String role) {
        return isGranted(role);
    }

    /**
     * Returns the <code>Authentication</code> (which is a subclass of
     * <code>Principal</code>), or <code>null</code> if unavailable.
     *
     * @return the <code>Authentication</code>, or <code>null</code>
     */
    public Principal getUserPrincipal() {
        Authentication auth = getAuthentication();

        if ((auth == null) || (auth.getPrincipal() == null)) {
            return null;
        }

        return auth;
    }

    private Authentication getAuthentication() {
        if ((ContextHolder.getContext() != null)
            && ContextHolder.getContext() instanceof SecureContext) {
            return ((SecureContext) ContextHolder.getContext())
            .getAuthentication();
        }

        return null;
    }

    private boolean isGranted(String role) {
        Authentication auth = getAuthentication();

        if ((auth == null) || (auth.getPrincipal() == null)
            || (auth.getAuthorities() == null)) {
            return false;
        }

        for (int i = 0; i < auth.getAuthorities().length; i++) {
            if (role.equals(auth.getAuthorities()[i].getAuthority())) {
                return true;
            }
        }

        return false;
    }
}
