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
package org.springframework.security.openid;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

/**
 * OpenID Authentication Token
 *
 * @author Robin Bramley
 * @version $Id$
 */
public class OpenIDAuthenticationToken extends AbstractAuthenticationToken {
    //~ Instance fields ================================================================================================

    private final OpenIDAuthenticationStatus status;
    private final String identityUrl;
    private final String message;

    //~ Constructors ===================================================================================================

    public OpenIDAuthenticationToken(OpenIDAuthenticationStatus status, String identityUrl, String message) {
        super(new ArrayList<GrantedAuthority>(0));
        this.status = status;
        this.identityUrl = identityUrl;
        this.message = message;
        setAuthenticated(false);
    }

    /**
     * Created by the OpenIDAuthenticationProvider on successful authentication.
     * <b>Do not use directly</b>
     *
     */
    public OpenIDAuthenticationToken(List<GrantedAuthority> authorities, OpenIDAuthenticationStatus status, String identityUrl) {
        super(authorities);
        this.status = status;
        this.identityUrl = identityUrl;
        this.message = null;

        setAuthenticated(true);
    }

    //~ Methods ========================================================================================================

    /**
     * Returns 'null' always, as no credentials are processed by the OpenID provider.
     * @see org.springframework.security.core.Authentication#getCredentials()
     */
    public Object getCredentials() {
        return null;
    }

    public String getIdentityUrl() {
        return identityUrl;
    }

    public String getMessage() {
        return message;
    }

    /**
     * Returns the <tt>identityUrl</tt> value.
     * @see org.springframework.security.core.Authentication#getPrincipal()
     */
    public Object getPrincipal() {
        return identityUrl;
    }

    public OpenIDAuthenticationStatus getStatus() {
        return status;
    }
}
