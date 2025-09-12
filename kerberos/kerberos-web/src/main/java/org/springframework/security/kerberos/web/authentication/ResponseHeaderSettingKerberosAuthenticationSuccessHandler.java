/*
 * Copyright 2004-present the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.kerberos.web.authentication;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.kerberos.authentication.KerberosServiceRequestToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

/**
 * Adds a WWW-Authenticate (or other) header to the response following successful
 * authentication.
 *
 * @author Jeremy Stone
 */
public class ResponseHeaderSettingKerberosAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

	private static final String NEGOTIATE_PREFIX = "Negotiate ";

	private static final String WWW_AUTHENTICATE = "WWW-Authenticate";

	private String headerName = WWW_AUTHENTICATE;

	private String headerPrefix = NEGOTIATE_PREFIX;

	/**
	 * Sets the name of the header to set. By default this is 'WWW-Authenticate'.
	 * @param headerName the www authenticate header name
	 */
	public void setHeaderName(String headerName) {
		this.headerName = headerName;
	}

	/**
	 * Sets the value of the prefix for the encoded response token value. By default this
	 * is 'Negotiate '.
	 * @param headerPrefix the negotiate prefix
	 */
	public void setHeaderPrefix(String headerPrefix) {
		this.headerPrefix = headerPrefix;
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		KerberosServiceRequestToken auth = (KerberosServiceRequestToken) authentication;
		if (auth.hasResponseToken()) {
			response.addHeader(this.headerName, this.headerPrefix + auth.getEncodedResponseToken());
		}
	}

}
