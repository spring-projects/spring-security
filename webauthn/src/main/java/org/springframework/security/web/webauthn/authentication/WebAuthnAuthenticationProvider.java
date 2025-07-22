/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.web.webauthn.authentication;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.management.RelyingPartyAuthenticationRequest;
import org.springframework.security.web.webauthn.management.WebAuthnRelyingPartyOperations;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationProvider} that uses {@link WebAuthnRelyingPartyOperations} for
 * authentication using an {@link WebAuthnAuthenticationRequestToken}. First
 * {@link WebAuthnRelyingPartyOperations#authenticate(RelyingPartyAuthenticationRequest)}
 * is invoked. The result is a username passed into {@link UserDetailsService}. The
 * {@link UserDetails} is used to create an {@link Authentication}.
 *
 * @author Rob Winch
 * @since 6.4
 */
public class WebAuthnAuthenticationProvider implements AuthenticationProvider {

	private final WebAuthnRelyingPartyOperations relyingPartyOperations;

	private final UserDetailsService userDetailsService;

	/**
	 * Creates a new instance.
	 * @param relyingPartyOperations the {@link WebAuthnRelyingPartyOperations} to use.
	 * Cannot be null.
	 * @param userDetailsService the {@link UserDetailsService} to use. Cannot be null.
	 */
	public WebAuthnAuthenticationProvider(WebAuthnRelyingPartyOperations relyingPartyOperations,
			UserDetailsService userDetailsService) {
		Assert.notNull(relyingPartyOperations, "relyingPartyOperations cannot be null");
		Assert.notNull(userDetailsService, "userDetailsService cannot be null");
		this.relyingPartyOperations = relyingPartyOperations;
		this.userDetailsService = userDetailsService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		WebAuthnAuthenticationRequestToken webAuthnRequest = (WebAuthnAuthenticationRequestToken) authentication;
		try {
			PublicKeyCredentialUserEntity userEntity = this.relyingPartyOperations
				.authenticate(webAuthnRequest.getWebAuthnRequest());
			String username = userEntity.getName();
			UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
			return new WebAuthnAuthentication(userEntity, userDetails.getAuthorities());
		}
		catch (RuntimeException ex) {
			throw new BadCredentialsException(ex.getMessage(), ex);
		}
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return WebAuthnAuthenticationRequestToken.class.isAssignableFrom(authentication);
	}

}
