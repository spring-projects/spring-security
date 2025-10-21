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

package org.springframework.security.web.authentication.preauth;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.function.Supplier;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jspecify.annotations.Nullable;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.Ordered;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.util.Assert;

/**
 * <p>
 * Processes a pre-authenticated authentication request. The request will typically
 * originate from a
 * {@link org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter}
 * subclass.
 *
 * <p>
 * This authentication provider will not perform any checks on authentication requests, as
 * they should already be pre-authenticated. However, the AuthenticationUserDetailsService
 * implementation may still throw a UsernameNotFoundException, for example.
 *
 * @author Ruud Senden
 * @since 2.0
 */
public class PreAuthenticatedAuthenticationProvider implements AuthenticationProvider, InitializingBean, Ordered {

	private static final Log logger = LogFactory.getLog(PreAuthenticatedAuthenticationProvider.class);

	@SuppressWarnings("NullAway.Init")
	private AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> preAuthenticatedUserDetailsService;

	private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();

	private Supplier<Collection<GrantedAuthority>> grantedAuthoritySupplier = List::of;

	private boolean throwExceptionWhenTokenRejected;

	private int order = -1; // default: same as non-ordered

	/**
	 * Check whether all required properties have been set.
	 */
	@Override
	public void afterPropertiesSet() {
		Assert.notNull(this.preAuthenticatedUserDetailsService, "An AuthenticationUserDetailsService must be set");
	}

	/**
	 * Authenticate the given PreAuthenticatedAuthenticationToken.
	 * <p>
	 * If the principal contained in the authentication object is null, the request will
	 * be ignored to allow other providers to authenticate it.
	 */
	@Override
	public @Nullable Authentication authenticate(Authentication authentication) throws AuthenticationException {
		if (!supports(authentication.getClass())) {
			return null;
		}
		logger.debug(LogMessage.format("PreAuthenticated authentication request: %s", authentication));
		if (authentication.getPrincipal() == null) {
			logger.debug("No pre-authenticated principal found in request.");
			if (this.throwExceptionWhenTokenRejected) {
				throw new BadCredentialsException("No pre-authenticated principal found in request.");
			}
			return null;
		}
		if (authentication.getCredentials() == null) {
			logger.debug("No pre-authenticated credentials found in request.");
			if (this.throwExceptionWhenTokenRejected) {
				throw new BadCredentialsException("No pre-authenticated credentials found in request.");
			}
			return null;
		}
		UserDetails userDetails = this.preAuthenticatedUserDetailsService
			.loadUserDetails((PreAuthenticatedAuthenticationToken) authentication);
		this.userDetailsChecker.check(userDetails);
		Collection<GrantedAuthority> authorities = new LinkedHashSet<>(userDetails.getAuthorities());
		authorities.addAll(this.grantedAuthoritySupplier.get());
		PreAuthenticatedAuthenticationToken result = new PreAuthenticatedAuthenticationToken(userDetails,
				authentication.getCredentials(), authorities);
		result.setDetails(authentication.getDetails());
		return result;
	}

	/**
	 * Indicate that this provider only supports PreAuthenticatedAuthenticationToken
	 * (sub)classes.
	 */
	@Override
	public final boolean supports(Class<?> authentication) {
		return PreAuthenticatedAuthenticationToken.class.isAssignableFrom(authentication);
	}

	/**
	 * Set the AuthenticatedUserDetailsService to be used to load the {@code UserDetails}
	 * for the authenticated user.
	 * @param uds
	 */
	public void setPreAuthenticatedUserDetailsService(
			AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> uds) {
		this.preAuthenticatedUserDetailsService = uds;
	}

	/**
	 * If true, causes the provider to throw a BadCredentialsException if the presented
	 * authentication request is invalid (contains a null principal or credentials).
	 * Otherwise it will just return null. Defaults to false.
	 */
	public void setThrowExceptionWhenTokenRejected(boolean throwExceptionWhenTokenRejected) {
		this.throwExceptionWhenTokenRejected = throwExceptionWhenTokenRejected;
	}

	/**
	 * Sets the strategy which will be used to validate the loaded <tt>UserDetails</tt>
	 * object for the user. Defaults to an {@link AccountStatusUserDetailsChecker}.
	 * @param userDetailsChecker
	 */
	public void setUserDetailsChecker(UserDetailsChecker userDetailsChecker) {
		Assert.notNull(userDetailsChecker, "userDetailsChecker cannot be null");
		this.userDetailsChecker = userDetailsChecker;
	}

	/**
	 * Sets authorities that this provider should grant once authentication completes
	 * @param grantedAuthoritySupplier the supplier that grants authorities
	 */
	public void setGrantedAuthoritySupplier(Supplier<Collection<GrantedAuthority>> grantedAuthoritySupplier) {
		Assert.notNull(grantedAuthoritySupplier, "grantedAuthoritySupplier cannot be null");
		this.grantedAuthoritySupplier = grantedAuthoritySupplier;
	}

	@Override
	public int getOrder() {
		return this.order;
	}

	public void setOrder(int i) {
		this.order = i;
	}

}
