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


import org.junit.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.MFAUserDetails;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class MultiFactorAuthenticationProviderTests {

	@Test
	public void authenticate_with_singleFactorAuthenticationAllowedOption_false_test(){
		AuthenticationProvider delegatedAuthenticationProvider = mock(AuthenticationProvider.class);
		MFAUserDetails userDetails = mock(MFAUserDetails.class);
		when(userDetails.isSingleFactorAuthenticationAllowed()).thenReturn(true);
		UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, Collections.emptyList());
		authenticationToken.setDetails(userDetails);
		when(delegatedAuthenticationProvider.supports(any())).thenReturn(true);
		when(delegatedAuthenticationProvider.authenticate(any()))
				.thenReturn(new UsernamePasswordAuthenticationToken(
						"principal",
						"credentials",
						Collections.singletonList(new SimpleGrantedAuthority("ROLE_DUMMY"))
				));

		MultiFactorAuthenticationProvider provider = new MultiFactorAuthenticationProvider(delegatedAuthenticationProvider, new MFATokenEvaluatorImpl());
		Authentication result = provider.authenticate(new UsernamePasswordAuthenticationToken("dummy", "dummy"));

		assertThat(result).isInstanceOf(MultiFactorAuthenticationToken.class);
		assertThat(result.getPrincipal()).isEqualTo("principal");
		assertThat(result.getCredentials()).isEqualTo("credentials");
		assertThat(result.getAuthorities()).isEmpty();

	}

	@Test
	public void authenticate_with_singleFactorAuthenticationAllowedOption_true_test(){
		AuthenticationProvider delegatedAuthenticationProvider = mock(AuthenticationProvider.class);
		MFAUserDetails userDetails = mock(MFAUserDetails.class);
		when(userDetails.isSingleFactorAuthenticationAllowed()).thenReturn(true);
		UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, Collections.emptyList());
		authenticationToken.setDetails(userDetails);
		when(delegatedAuthenticationProvider.supports(any())).thenReturn(true);
		when(delegatedAuthenticationProvider.authenticate(any()))
				.thenReturn(authenticationToken);

		MultiFactorAuthenticationProvider provider = new MultiFactorAuthenticationProvider(delegatedAuthenticationProvider, new MFATokenEvaluatorImpl());
		Authentication result = provider.authenticate(new UsernamePasswordAuthenticationToken("dummy", "dummy"));

		assertThat(result).isInstanceOf(UsernamePasswordAuthenticationToken.class);
		assertThat(result).isEqualTo(result);
	}

	@Test(expected = IllegalArgumentException.class)
	public void authenticate_with_invalid_AuthenticationToken_test(){
		AuthenticationProvider delegatedAuthenticationProvider = mock(AuthenticationProvider.class);
		when(delegatedAuthenticationProvider.supports(any())).thenReturn(false);

		MultiFactorAuthenticationProvider provider = new MultiFactorAuthenticationProvider(delegatedAuthenticationProvider, new MFATokenEvaluatorImpl());
		provider.authenticate(new TestingAuthenticationToken("dummy", "dummy"));
	}

}
