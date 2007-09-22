/* Copyright 2004-2007 Acegi Technology Pty Limited
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

package org.springframework.security.ui.ntlm;

import jcifs.smb.NtlmPasswordAuthentication;

import org.springframework.security.providers.UsernamePasswordAuthenticationToken;

/**
 * An NTLM-specific {@link UsernamePasswordAuthenticationToken} that allows
 * any provider to bypass the problem of an empty password since NTLM does
 * not retrieve the user's password from the PDC.
 * 
 * @author Sylvain Mougenot
 */
public class NtlmUsernamePasswordAuthenticationToken extends UsernamePasswordAuthenticationToken {

	private static final long serialVersionUID = 1L;
	
	/**
	 * ACEGI often checks password ; but we do not have one. This is the replacement password 
	 */
	public static final String DEFAULT_PASSWORD = "";

	/**
	 * Create an NTLM {@link UsernamePasswordAuthenticationToken} using the
	 * JCIFS {@link NtlmPasswordAuthentication} object.
	 * 
	 * @param ntlmAuth		The {@link NtlmPasswordAuthentication} object.
	 * @param stripDomain	Uses just the username if <code>true</code>,
	 * 						otherwise use the username and domain name.
	 */
	public NtlmUsernamePasswordAuthenticationToken(final NtlmPasswordAuthentication ntlmAuth, final boolean stripDomain) {
		super((stripDomain) ? ntlmAuth.getUsername() : ntlmAuth.getName(), DEFAULT_PASSWORD);
	}
}
