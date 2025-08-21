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

package org.springframework.security.authentication.ott;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationProvider} responsible for authenticating users based on
 * one-time tokens. It uses an {@link OneTimeTokenService} to consume tokens and an
 * {@link UserDetailsService} to fetch user authorities.
 *
 * @author Marcus da Coregio
 * @author Andrey Litvitski
 * @since 6.4
 */
public final class OneTimeTokenAuthenticationProvider implements AuthenticationProvider, MessageSourceAware {

	private final OneTimeTokenService oneTimeTokenService;

	private final UserDetailsService userDetailsService;

	private final Log logger = LogFactory.getLog(getClass());

	private UserDetailsChecker authenticationChecks = new DefaultAuthenticationChecks();

	private MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

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
		try {
			UserDetails user = this.userDetailsService.loadUserByUsername(consumed.getUsername());
			this.authenticationChecks.check(user);
			OneTimeTokenAuthenticationToken authenticated = OneTimeTokenAuthenticationToken.authenticated(user,
					user.getAuthorities());
			authenticated.setDetails(otpAuthenticationToken.getDetails());
			return authenticated;
		}
		catch (UsernameNotFoundException ex) {
			throw new BadCredentialsException("Failed to authenticate the one-time token");
		}
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OneTimeTokenAuthenticationToken.class.isAssignableFrom(authentication);
	}

	@Override
	public void setMessageSource(MessageSource messageSource) {
		this.messages = new MessageSourceAccessor(messageSource);
	}

	public void setAuthenticationChecks(UserDetailsChecker authenticationChecks) {
		this.authenticationChecks = authenticationChecks;
	}

	private class DefaultAuthenticationChecks implements UserDetailsChecker {

		@Override
		public void check(UserDetails user) {
			if (!user.isAccountNonLocked()) {
				OneTimeTokenAuthenticationProvider.this.logger
					.debug("Failed to authenticate since user account is locked");
				throw new LockedException(OneTimeTokenAuthenticationProvider.this.messages
					.getMessage("AbstractUserDetailsAuthenticationProvider.locked", "User account is locked"));
			}
			if (!user.isEnabled()) {
				OneTimeTokenAuthenticationProvider.this.logger
					.debug("Failed to authenticate since user account is disabled");
				throw new DisabledException(OneTimeTokenAuthenticationProvider.this.messages
					.getMessage("AbstractUserDetailsAuthenticationProvider.disabled", "User is disabled"));
			}
			if (!user.isAccountNonExpired()) {
				OneTimeTokenAuthenticationProvider.this.logger
					.debug("Failed to authenticate since user account has expired");
				throw new AccountExpiredException(OneTimeTokenAuthenticationProvider.this.messages
					.getMessage("AbstractUserDetailsAuthenticationProvider.expired", "User account has expired"));
			}
		}

	}

}
