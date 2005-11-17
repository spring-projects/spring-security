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

import jcifs.Config;
import jcifs.UniAddress;

import jcifs.smb.NtlmPasswordAuthentication;

import org.acegisecurity.Authentication;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;

import java.net.UnknownHostException;


/**
 * Provides authentication of a basic {@link
 * UsernamePasswordAuthenticationToken } on a ntlm domain via smb/cifs.
 *
 * @author Davide Baroncelli
 * @version $Id$
 */
public class SmbBasicAuthenticationProvider
    extends AbstractSmbAuthenticationProvider {
    //~ Instance fields ========================================================

    String domainController;

    //~ Methods ================================================================

    public void setDomainController(String domainController) {
        this.domainController = domainController;
    }

    public boolean supports(Class authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

    protected UniAddress getDomainController(Authentication authentication,
        NtlmPasswordAuthentication ntlmAuthentication) {
        try {
            if (domainController == null) {
                domainController = Config.getProperty("jcifs.smb.client.domain");
            }

            String domain = domainController;

            if (domain == null) {
                domain = ntlmAuthentication.getDomain();
            }

            UniAddress dc = UniAddress.getByName(domain, true);

            return dc;
        } catch (UnknownHostException uhe) {
            throw new BadCredentialsException(
                "no host could be found for the name "
                + ntlmAuthentication.getDomain(), uhe);
        }
    }

    protected NtlmPasswordAuthentication getNtlmPasswordAuthentication(
        Authentication authentication) {
        UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) authentication;
        String username = token.getPrincipal().toString();
        String password = (String) token.getCredentials();
        int index = username.indexOf('\\');

        if (index == -1) {
            index = username.indexOf('/');
        }

        // if domain is null then the jcifs default is used
        // (this is set through the "jcifs.smb.client.domain" Config property)
        String domain = (index != -1) ? username.substring(0, index) : null;
        username = (index != -1) ? username.substring(index + 1) : username;

        NtlmPasswordAuthentication ntlm = new NtlmPasswordAuthentication(domain,
                username, password);

        return ntlm;
    }
}
