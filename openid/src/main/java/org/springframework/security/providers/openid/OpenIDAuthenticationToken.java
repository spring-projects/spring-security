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
package org.springframework.security.providers.openid;

import org.springframework.security.GrantedAuthority;

import org.springframework.security.providers.AbstractAuthenticationToken;


/**
 * OpenID Authentication Token
 *
 * @author Robin Bramley, Opsera Ltd
 */
public class OpenIDAuthenticationToken extends AbstractAuthenticationToken {
    //~ Instance fields ================================================================================================

    private OpenIDAuthenticationStatus status;
    private String identityUrl;
    private String message;

    //~ Constructors ===================================================================================================

    public OpenIDAuthenticationToken(OpenIDAuthenticationStatus status, String identityUrl, String message) {
        super(new GrantedAuthority[0]);
        this.status = status;
        this.identityUrl = identityUrl;
        this.message = message;
        setAuthenticated(false);
    }

/**
     * Created by the OpenIDAuthenticationProvider on successful authentication.
     * <b>Do not use directly</b>
     *
     * @param authorities
     * @param status
     * @param identityUrl
     */
    public OpenIDAuthenticationToken(GrantedAuthority[] authorities, OpenIDAuthenticationStatus status, String identityUrl) {
        super(authorities);
        this.status = status;
        this.identityUrl = identityUrl;

        setAuthenticated(true);
    }

    //~ Methods ========================================================================================================

    /* (non-Javadoc)
     * @see org.springframework.security.Authentication#getCredentials()
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

    /* (non-Javadoc)
     * @see org.springframework.security.Authentication#getPrincipal()
     */
    public Object getPrincipal() {
        return identityUrl;
    }

    public OpenIDAuthenticationStatus getStatus() {
        return status;
    }
}
