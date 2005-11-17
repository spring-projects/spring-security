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
import jcifs.smb.SmbAuthException;
import jcifs.smb.SmbException;
import jcifs.smb.SmbSession;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.providers.AuthenticationProvider;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


/**
 * An {@link AuthenticationProvider} implementation that relies on <a
 * href="http://www.jcifs.org">jcifs</a> in order to provide an authentication
 * service on a Windows network. This implementation relies on a {@link
 * #setAuthorizationProvider(AuthenticationProvider) delegate provider} in
 * order for authorization information to be filled into the authorized {@link
 * Authentication token}. Subclasses must implement the logic that {@link
 * #getNtlmPasswordAuthentication(Authentication) extracts the jcifs }{@link
 * NtlmPasswordAuthentication } object from the particular {@link
 * Authentication } token implementation and the one that {@link
 * #getDomainController(Authentication, NtlmPasswordAuthentication) extracts
 * the domain controller address }.
 *
 * @author Davide Baroncelli
 * @version $Id$
 */
public abstract class AbstractSmbAuthenticationProvider
    implements AuthenticationProvider {
    //~ Instance fields ========================================================

    private AuthenticationProvider authorizationProvider;
    private Log log = LogFactory.getLog(this.getClass());

    //~ Methods ================================================================

    /**
     * DOCUMENT ME!
     *
     * @param authorizationProvider The {@link AuthenticationProvider } which
     *        will be contacted in order for it to fill authorization info in
     *        the (already authenticated) {@link Authentication } object that
     *        they will be passed.
     */
    public void setAuthorizationProvider(
        AuthenticationProvider authorizationProvider) {
        this.authorizationProvider = authorizationProvider;
    }

    public Authentication authenticate(Authentication authentication)
        throws AuthenticationException {
        NtlmPasswordAuthentication ntlm = getNtlmPasswordAuthentication(authentication);
        UniAddress dc = getDomainController(authentication, ntlm);

        return performAuthentication(dc, ntlm, authentication);
    }

    protected abstract UniAddress getDomainController(
        Authentication authentication,
        NtlmPasswordAuthentication ntlmAuthentication);

    protected abstract NtlmPasswordAuthentication getNtlmPasswordAuthentication(
        Authentication authentication);

    protected Authentication performAuthentication(UniAddress dc,
        NtlmPasswordAuthentication ntlm, Authentication authentication) {
        try {
            // this performs authentication...
            SmbSession.logon(dc, ntlm);

            if (log.isDebugEnabled()) {
                log.debug(ntlm + " successfully authenticated against " + dc);
            }

            // ...and this performs authorization.
            Authentication authorizedResult = authorizationProvider
                .authenticate(authentication);

            return authorizedResult;
        } catch (SmbException se) {
            log.error(ntlm.getName() + ": 0x"
                + jcifs.util.Hexdump.toHexString(se.getNtStatus(), 8) + ": "
                + se);

            if (se instanceof SmbAuthException) {
                SmbAuthException sae = (SmbAuthException) se;

                if (se.getNtStatus() == SmbAuthException.NT_STATUS_ACCESS_VIOLATION) {
                    throw new ChallengeExpiredException(sae.getMessage(), sae);
                } else {
                    throw new BadCredentialsException(sae.getMessage(), sae);
                }
            } else {
                throw new AuthenticationServiceException(se.getMessage(), se);
            }
        }
    }
}
