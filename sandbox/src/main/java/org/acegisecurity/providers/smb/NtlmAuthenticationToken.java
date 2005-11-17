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

package org.acegisecurity.providers.smb;

import jcifs.UniAddress;

import jcifs.smb.NtlmPasswordAuthentication;

import org.acegisecurity.Authentication;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.AbstractAuthenticationToken;


/**
 * {@link Authentication } implementation for NTLM smb authentication.
 *
 * @author Davide Baroncelli
 * @version $Id$
 *
 * @see org.acegisecurity.ui.ntlm.NtlmProcessingFilter
 * @see org.acegisecurity.providers.smb.SmbNtlmAuthenticationProvider
 */
public class NtlmAuthenticationToken extends AbstractAuthenticationToken {
    //~ Instance fields ========================================================

    private NtlmPasswordAuthentication ntlmPasswordAuthentication;
    private transient UniAddress domainController;
    private GrantedAuthority[] authorities;
    private boolean authenticated;

    //~ Constructors ===========================================================

    public NtlmAuthenticationToken(
        NtlmPasswordAuthentication ntlmPasswordAuthentication,
        UniAddress domainController) {
        this.ntlmPasswordAuthentication = ntlmPasswordAuthentication;
        this.domainController = domainController;
    }

    //~ Methods ================================================================

    public void setAuthenticated(boolean isAuthenticated) {
        this.authenticated = isAuthenticated;
    }

    public boolean isAuthenticated() {
        return authenticated;
    }

    public void setAuthorities(GrantedAuthority[] authorities) {
        this.authorities = authorities;
    }

    public GrantedAuthority[] getAuthorities() {
        return authorities;
    }

    public Object getCredentials() {
        return ntlmPasswordAuthentication.getPassword();
    }

    public UniAddress getDomainController() {
        return domainController;
    }

    public NtlmPasswordAuthentication getNtlmPasswordAuthentication() {
        return ntlmPasswordAuthentication;
    }

    public Object getPrincipal() {
        return ntlmPasswordAuthentication.getUsername();
    }
}
