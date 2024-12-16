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

package org.springframework.security.authentication.ott;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationProvider} responsible for authenticating users based on
 * one-time tokens. It uses an {@link OneTimeTokenService} to consume tokens and an
 * {@link UserDetailsService} to fetch user authorities.
 *
 * @author Marcus da Coregio
 * @since 6.4
 */
public final class OneTimeTokenAuthenticationProvider implements AuthenticationProvider {

	private final OneTimeTokenService oneTimeTokenService;

	private final UserDetailsService userDetailsService;

	public OneTimeTokenAuthenticationProvider(OneTimeTokenService oneTimeTokenService,
			UserDetailsService userDetailsService) {
		Assert.notNull(oneTimeTokenService, "oneTimeTokenService cannot be null");
		Assert.notNull(userDetailsService, "userDetailsService cannot be null");
		this.userDetailsService = userDetailsService;
		this.oneTimeTokenService = oneTimeTokenService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OneTimeTokenAuthenticationToken otpAuthenticationToken = (OneTimeTokenAuthenticationToken) authentication;
		OneTimeToken consumed = this.oneTimeTokenService.consume(otpAuthenticationToken);
		if (consumed == null) {
			throw new InvalidOneTimeTokenException("Invalid token");
		}
		UserDetails user = this.userDetailsService.loadUserByUsername(consumed.getUsername());
		OneTimeTokenAuthenticationToken authenticated = OneTimeTokenAuthenticationToken.authenticated(user,
				user.getAuthorities());
		authenticated.setDetails(otpAuthenticationToken.getDetails());
		return authenticated;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OneTimeTokenAuthenticationToken.class.isAssignableFrom(authentication);
	}

}
