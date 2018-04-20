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

import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.MFATokenEvaluator;
import org.springframework.security.authentication.MultiFactorAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.ProviderManagerBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.springframework.security.config.annotation.authentication.configurers.mfa.MultiFactorAuthenticationProviderConfigurer.multiFactorAuthenticationProvider;

public class MultiFactorAuthenticationProviderConfigurerTests {

	@Test
	public void test(){
		AuthenticationProvider delegatedAuthenticationProvider = mock(AuthenticationProvider.class);
		MFATokenEvaluator mfaTokenEvaluator = mock(MFATokenEvaluator.class);
		MultiFactorAuthenticationProviderConfigurer configurer
				= multiFactorAuthenticationProvider(delegatedAuthenticationProvider);
		configurer.mfaTokenEvaluator(mfaTokenEvaluator);
		ProviderManagerBuilder providerManagerBuilder = mock(ProviderManagerBuilder.class);
		configurer.configure(providerManagerBuilder);
		ArgumentCaptor<AuthenticationProvider> argumentCaptor = ArgumentCaptor.forClass(AuthenticationProvider.class);
		verify(providerManagerBuilder).authenticationProvider(argumentCaptor.capture());
		MultiFactorAuthenticationProvider authenticationProvider = (MultiFactorAuthenticationProvider) argumentCaptor.getValue();

		assertThat(authenticationProvider.getAuthenticationProvider()).isEqualTo(delegatedAuthenticationProvider);
		assertThat(authenticationProvider.getMFATokenEvaluator()).isEqualTo(mfaTokenEvaluator);
	}
}
