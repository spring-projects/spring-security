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

package org.springframework.security.kerberos.authentication;

import org.jspecify.annotations.Nullable;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * {@link AuthenticationProvider} for kerberos.
 *
 * @author Mike Wiesner
 * @author Bogdan Mustiata
 * @since 1.0
 */
public class KerberosAuthenticationProvider implements AuthenticationProvider {

	private @Nullable KerberosClient kerberosClient;

	private @Nullable UserDetailsService userDetailsService;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		UsernamePasswordAuthenticationToken auth = (UsernamePasswordAuthenticationToken) authentication;
		if (this.kerberosClient == null) {
			throw new IllegalStateException("kerberosClient must be set");
		}
		if (this.userDetailsService == null) {
			throw new IllegalStateException("userDetailsService must be set");
		}
		Object credentials = auth.getCredentials();
		if (credentials == null) {
			throw new IllegalArgumentException("credentials cannot be null");
		}
		JaasSubjectHolder subjectHolder = this.kerberosClient.login(auth.getName(), credentials.toString());
		String username = subjectHolder.getUsername();
		if (username == null) {
			throw new IllegalStateException("username cannot be null");
		}
		UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
		KerberosUsernamePasswordAuthenticationToken output = new KerberosUsernamePasswordAuthenticationToken(
				userDetails, credentials, userDetails.getAuthorities(), subjectHolder);
		output.setDetails(authentication.getDetails());
		return output;

	}

	@Override
	public boolean supports(Class<? extends Object> authentication) {
		return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
	}

	/**
	 * Sets the kerberos client.
	 * @param kerberosClient the new kerberos client
	 */
	public void setKerberosClient(KerberosClient kerberosClient) {
		this.kerberosClient = kerberosClient;
	}

	/**
	 * Sets the user details service.
	 * @param detailsService the new user details service
	 */
	public void setUserDetailsService(UserDetailsService detailsService) {
		this.userDetailsService = detailsService;
	}

}
