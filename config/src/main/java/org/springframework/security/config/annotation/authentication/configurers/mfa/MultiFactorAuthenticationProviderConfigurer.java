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

package org.springframework.security.config.annotation.authentication.configurers.mfa;

import org.springframework.security.authentication.*;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.authentication.ProviderManagerBuilder;

/**
 * Allows configuring a {@link MultiFactorAuthenticationProvider}
 *
 * @param <B> the type of the {@link ProviderManagerBuilder}
 *
 * @author Yoshikazu Nojima
 */
public class MultiFactorAuthenticationProviderConfigurer<B extends ProviderManagerBuilder<B>>
		extends SecurityConfigurerAdapter<AuthenticationManager, B> {

	//~ Instance fields
	// ================================================================================================
	private AuthenticationProvider authenticationProvider;
	private MFATokenEvaluator mfaTokenEvaluator = new MFATokenEvaluatorImpl();

	/**
	 * Constructor
	 * @param authenticationProvider {@link AuthenticationProvider} to be delegated
	 */
	public MultiFactorAuthenticationProviderConfigurer(AuthenticationProvider authenticationProvider) {
		this.authenticationProvider = authenticationProvider;
	}


	public static MultiFactorAuthenticationProviderConfigurer multiFactorAuthenticationProvider(AuthenticationProvider authenticationProvider){
		return new MultiFactorAuthenticationProviderConfigurer(authenticationProvider);
	}

	@Override
	public void configure(B builder) {
		MultiFactorAuthenticationProvider multiFactorAuthenticationProvider = new MultiFactorAuthenticationProvider(authenticationProvider, mfaTokenEvaluator);
		multiFactorAuthenticationProvider = postProcess(multiFactorAuthenticationProvider);
		builder.authenticationProvider(multiFactorAuthenticationProvider);
	}

	public MultiFactorAuthenticationProviderConfigurer<B> mfaTokenEvaluator(MFATokenEvaluator mfaTokenEvaluator) {
		this.mfaTokenEvaluator = mfaTokenEvaluator;
		return this;
	}
}
