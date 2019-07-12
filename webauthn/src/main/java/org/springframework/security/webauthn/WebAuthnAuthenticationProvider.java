/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.webauthn;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.webauthn.authenticator.WebAuthnAuthenticator;
import org.springframework.security.webauthn.authenticator.WebAuthnAuthenticatorService;
import org.springframework.security.webauthn.exception.CredentialIdNotFoundException;
import org.springframework.security.webauthn.userdetails.WebAuthnUserDetails;
import org.springframework.security.webauthn.userdetails.WebAuthnUserDetailsChecker;
import org.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;

/**
 * An {@link AuthenticationProvider} implementation for processing {@link WebAuthnAssertionAuthenticationToken}
 *
 * @author Yoshikazu Nojima
 */
public class WebAuthnAuthenticationProvider implements AuthenticationProvider {

	//~ Instance fields
	// ================================================================================================

	protected final Log logger = LogFactory.getLog(getClass());

	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
	private WebAuthnUserDetailsService userDetailsService;
	private WebAuthnAuthenticatorService authenticatorService;
	private WebAuthnManager webAuthnManager;
	private boolean forcePrincipalAsString = false;
	private boolean hideCredentialIdNotFoundExceptions = true;
	private WebAuthnUserDetailsChecker preAuthenticationChecks = new DefaultPreAuthenticationChecks();
	private WebAuthnUserDetailsChecker postAuthenticationChecks = new DefaultPostAuthenticationChecks();
	private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

	// ~ Constructor
	// ========================================================================================================

	public WebAuthnAuthenticationProvider(
			WebAuthnUserDetailsService userDetailsService,
			WebAuthnAuthenticatorService authenticatorService,
			WebAuthnManager webAuthnManager) {

		Assert.notNull(userDetailsService, "userDetailsService must not be null");
		Assert.notNull(authenticatorService, "authenticatorService must not be null");
		Assert.notNull(webAuthnManager, "webAuthnManager must not be null");

		this.userDetailsService = userDetailsService;
		this.authenticatorService = authenticatorService;
		this.webAuthnManager = webAuthnManager;
	}

	// ~ Methods
	// ========================================================================================================

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Authentication authenticate(Authentication authentication) {
		if (!supports(authentication.getClass())) {
			throw new IllegalArgumentException("Only WebAuthnAssertionAuthenticationToken is supported, " + authentication.getClass() + " was attempted");
		}

		WebAuthnAssertionAuthenticationToken authenticationToken = (WebAuthnAssertionAuthenticationToken) authentication;

		WebAuthnAuthenticationData credentials = authenticationToken.getCredentials();
		if (credentials == null) {
			logger.debug("Authentication failed: no credentials provided");

			throw new BadCredentialsException(messages.getMessage(
					"WebAuthnAuthenticationContextValidator.badCredentials",
					"Bad credentials"));
		}

		byte[] credentialId = credentials.getCredentialId();

		WebAuthnUserDetails user = retrieveWebAuthnUserDetails(credentialId);
		WebAuthnAuthenticator authenticator = user.getAuthenticators().stream()
				.filter(item -> Arrays.equals(item.getCredentialId(), credentialId))
				.findFirst()
				.orElse(null);

		preAuthenticationChecks.check(user);
		doAuthenticate(authenticationToken, authenticator, user);
		postAuthenticationChecks.check(user);

		//noinspection ConstantConditions
		authenticatorService.updateCounter(credentialId, authenticator.getCounter());

		Serializable principalToReturn = user;

		if (forcePrincipalAsString) {
			principalToReturn = user.getUsername();
		}

		WebAuthnAuthenticationToken result = new WebAuthnAuthenticationToken(
				principalToReturn, authenticationToken.getCredentials(),
				authoritiesMapper.mapAuthorities(user.getAuthorities()));
		result.setDetails(authenticationToken.getDetails());

		return result;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean supports(Class<?> authentication) {
		return WebAuthnAssertionAuthenticationToken.class.isAssignableFrom(authentication);
	}

	void doAuthenticate(WebAuthnAssertionAuthenticationToken authenticationToken, WebAuthnAuthenticator webAuthnAuthenticator, WebAuthnUserDetails user) {

		WebAuthnAuthenticationData webAuthnAuthenticationData = authenticationToken.getCredentials();
		boolean userVerificationRequired = isUserVerificationRequired(user, webAuthnAuthenticationData);
		webAuthnAuthenticationData = new WebAuthnAuthenticationData(
				webAuthnAuthenticationData.getCredentialId(),
				webAuthnAuthenticationData.getClientDataJSON(),
				webAuthnAuthenticationData.getAuthenticatorData(),
				webAuthnAuthenticationData.getSignature(),
				webAuthnAuthenticationData.getClientExtensionsJSON(),
				webAuthnAuthenticationData.getServerProperty(),
				userVerificationRequired,
				webAuthnAuthenticationData.isUserPresenceRequired(),
				webAuthnAuthenticationData.getExpectedAuthenticationExtensionIds()
		);

		webAuthnManager.verifyAuthenticationData(webAuthnAuthenticationData, webAuthnAuthenticator);

	}

	public boolean isForcePrincipalAsString() {
		return forcePrincipalAsString;
	}

	public void setForcePrincipalAsString(boolean forcePrincipalAsString) {
		this.forcePrincipalAsString = forcePrincipalAsString;
	}

	public boolean isHideCredentialIdNotFoundExceptions() {
		return hideCredentialIdNotFoundExceptions;
	}

	/**
	 * By default the <code>WebAuthnAuthenticationProvider</code> throws a
	 * <code>BadCredentialsException</code> if a credentialId is not found or the credential is
	 * incorrect. Setting this property to <code>false</code> will cause
	 * <code>CredentialIdNotFoundException</code>s to be thrown instead for the former. Note
	 * this is considered less secure than throwing <code>BadCredentialsException</code>
	 * for both exceptions.
	 *
	 * @param hideCredentialIdNotFoundExceptions set to <code>false</code> if you wish
	 *                                           <code>CredentialIdNotFoundException</code>s to be thrown instead of the non-specific
	 *                                           <code>BadCredentialsException</code> (defaults to <code>true</code>)
	 */
	public void setHideCredentialIdNotFoundExceptions(boolean hideCredentialIdNotFoundExceptions) {
		this.hideCredentialIdNotFoundExceptions = hideCredentialIdNotFoundExceptions;
	}

	protected WebAuthnUserDetailsService getUserDetailsService() {
		return userDetailsService;
	}

	public void setUserDetailsService(WebAuthnUserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

	protected WebAuthnUserDetailsChecker getPreAuthenticationChecks() {
		return preAuthenticationChecks;
	}

	/**
	 * Sets the policy will be used to verify the status of the loaded
	 * <code>WebAuthnUserDetails</code> <em>before</em> validation of the credentials takes place.
	 *
	 * @param preAuthenticationChecks strategy to be invoked prior to authentication.
	 */
	public void setPreAuthenticationChecks(WebAuthnUserDetailsChecker preAuthenticationChecks) {
		this.preAuthenticationChecks = preAuthenticationChecks;
	}

	protected WebAuthnUserDetailsChecker getPostAuthenticationChecks() {
		return postAuthenticationChecks;
	}

	public void setPostAuthenticationChecks(WebAuthnUserDetailsChecker postAuthenticationChecks) {
		this.postAuthenticationChecks = postAuthenticationChecks;
	}

	WebAuthnUserDetails retrieveWebAuthnUserDetails(byte[] credentialId) {
		WebAuthnUserDetails user;
		try {
			user = userDetailsService.loadWebAuthnUserByCredentialId(credentialId);
		} catch (CredentialIdNotFoundException notFound) {
			if (hideCredentialIdNotFoundExceptions) {
				throw new BadCredentialsException(messages.getMessage(
						"WebAuthnAuthenticationProvider.badCredentials",
						"Bad credentials"));
			} else {
				throw notFound;
			}
		} catch (Exception repositoryProblem) {
			throw new InternalAuthenticationServiceException(repositoryProblem.getMessage(), repositoryProblem);
		}

		if (user == null) {
			throw new InternalAuthenticationServiceException(
					"UserDetailsService returned null, which is an interface contract violation");
		}
		return user;
	}

	boolean isUserVerificationRequired(WebAuthnUserDetails user, WebAuthnAuthenticationData credentials) {

		Authentication currentAuthentication = SecurityContextHolder.getContext().getAuthentication();

		// If current authentication is authenticated and username matches, return false
		if (currentAuthentication != null && currentAuthentication.isAuthenticated() && Objects.equals(currentAuthentication.getName(), user.getUsername())) {
			return false;
		} else {
			return credentials.isUserVerificationRequired();
		}
	}

	private class DefaultPreAuthenticationChecks implements WebAuthnUserDetailsChecker {
		@Override
		public void check(WebAuthnUserDetails user) {
			if (!user.isAccountNonLocked()) {
				logger.debug("User account is locked");

				throw new LockedException(messages.getMessage(
						"WebAuthnAuthenticationProvider.locked",
						"User account is locked"));
			}

			if (!user.isEnabled()) {
				logger.debug("User account is disabled");

				throw new DisabledException(messages.getMessage(
						"WebAuthnAuthenticationProvider.disabled",
						"User is disabled"));
			}

			if (!user.isAccountNonExpired()) {
				logger.debug("User account is expired");

				throw new AccountExpiredException(messages.getMessage(
						"WebAuthnAuthenticationProvider.expired",
						"User account has expired"));
			}
		}
	}

	private class DefaultPostAuthenticationChecks implements WebAuthnUserDetailsChecker {
		@Override
		public void check(WebAuthnUserDetails user) {
			if (!user.isCredentialsNonExpired()) {
				logger.debug("User account credentials have expired");

				throw new CredentialsExpiredException(messages.getMessage(
						"WebAuthnAuthenticationProvider.credentialsExpired",
						"User credentials have expired"));
			}
		}
	}
}
