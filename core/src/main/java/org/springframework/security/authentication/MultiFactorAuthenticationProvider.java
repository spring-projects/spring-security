/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.authentication;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.util.Assert;

import java.util.Collections;

/**
 * An {@link AuthenticationProvider} implementation for the first factor(step) of multi factor authentication.
 * Authentication itself is delegated to another {@link AuthenticationProvider}.
 *
 * @author Yoshikazu Nojima
 */
public class MultiFactorAuthenticationProvider implements AuthenticationProvider {


	// ~ Instance fields
	// ================================================================================================
	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

	/**
	 * {@link AuthenticationProvider} to be delegated
	 */
	private AuthenticationProvider authenticationProvider;
	private MFATokenEvaluator mfaTokenEvaluator;

	/**
	 * Constructor
	 *
	 * @param authenticationProvider {@link AuthenticationProvider} to be delegated
	 */
	public MultiFactorAuthenticationProvider(AuthenticationProvider authenticationProvider, MFATokenEvaluator mfaTokenEvaluator) {
		Assert.notNull(authenticationProvider, "authenticationProvider must be set");
		Assert.notNull(mfaTokenEvaluator, "mfaTokenEvaluator must be set");
		this.authenticationProvider = authenticationProvider;
		this.mfaTokenEvaluator = mfaTokenEvaluator;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Authentication authenticate(Authentication authentication) {
		if (!supports(authentication.getClass())) {
			throw new IllegalArgumentException("Not supported AuthenticationToken " + authentication.getClass() + " was attempted");
		}

		Authentication result = authenticationProvider.authenticate(authentication);

		if (mfaTokenEvaluator.isSingleFactorAuthenticationAllowed(result)) {
			return result;
		}

		return new MultiFactorAuthenticationToken(
				result.getPrincipal(),
				result.getCredentials(),
				Collections.emptyList() // result.getAuthorities() is not used as not to inherit authorities from result
		);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean supports(Class<?> authentication) {
		return authenticationProvider.supports(authentication);
	}

	/**
	 * {@link AuthenticationProvider} to be delegated
	 */
	public AuthenticationProvider getAuthenticationProvider() {
		return authenticationProvider;
	}

	public MFATokenEvaluator getMFATokenEvaluator() {
		return mfaTokenEvaluator;
	}
}
