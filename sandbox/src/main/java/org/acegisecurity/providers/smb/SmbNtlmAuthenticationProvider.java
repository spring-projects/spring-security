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

package net.sf.acegisecurity.providers.smb;

import jcifs.UniAddress;

import jcifs.smb.NtlmPasswordAuthentication;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.ui.ntlm.NtlmProcessingFilter;


/**
 * This class provides authentication through smb of {@link
 * NtlmAuthenticationToken } (i.e. tokens obtained through the NTLM
 * Authorization method by {@link NtlmProcessingFilter } ).
 *
 * @author Davide Baroncelli
 * @version $Id$
 *
 * @see net.sf.acegisecurity.ui.ntlm.NtlmProcessingFilter
 */
public class SmbNtlmAuthenticationProvider
    extends AbstractSmbAuthenticationProvider {
    //~ Methods ================================================================

    public boolean supports(Class authentication) {
        return NtlmAuthenticationToken.class.isAssignableFrom(authentication);
    }

    protected UniAddress getDomainController(Authentication authentication,
        NtlmPasswordAuthentication ntlmAuthentication) {
        NtlmAuthenticationToken ntlmToken = (NtlmAuthenticationToken) authentication;
        UniAddress dc = ntlmToken.getDomainController();

        return dc;
    }

    protected NtlmPasswordAuthentication getNtlmPasswordAuthentication(
        Authentication authentication) {
        NtlmAuthenticationToken ntlmToken = (NtlmAuthenticationToken) authentication;
        NtlmPasswordAuthentication ntlm = ntlmToken
            .getNtlmPasswordAuthentication();

        return ntlm;
    }
}
