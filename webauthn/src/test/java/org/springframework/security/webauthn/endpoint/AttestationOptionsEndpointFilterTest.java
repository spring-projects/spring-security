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

package org.springframework.security.webauthn.endpoint;

import com.webauthn4j.converter.util.JsonConverter;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.*;
import org.springframework.security.webauthn.options.AttestationOptions;
import org.springframework.security.webauthn.options.OptionsProvider;

import javax.servlet.ServletException;
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.security.webauthn.endpoint.AttestationOptionsEndpointFilter.FILTER_URL;

public class AttestationOptionsEndpointFilterTest {

	private JsonConverter jsonConverter = new JsonConverter();

	@Test
	public void getter_setter_test() {
		AttestationOptionsEndpointFilter attestationOptionsEndpointFilter = new AttestationOptionsEndpointFilter(mock(OptionsProvider.class), jsonConverter);
		MFATokenEvaluator mfaTokenEvaluator = new MFATokenEvaluatorImpl();
		AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
		attestationOptionsEndpointFilter.setMFATokenEvaluator(mfaTokenEvaluator);
		attestationOptionsEndpointFilter.setTrustResolver(trustResolver);
		assertThat(attestationOptionsEndpointFilter.getMFATokenEvaluator()).isEqualTo(mfaTokenEvaluator);
		assertThat(attestationOptionsEndpointFilter.getTrustResolver()).isEqualTo(trustResolver);
	}

	@Test
	public void afterPropertiesSet_test() {
		AttestationOptionsEndpointFilter attestationOptionsEndpointFilter = new AttestationOptionsEndpointFilter(mock(OptionsProvider.class), jsonConverter);
		assertThatCode(attestationOptionsEndpointFilter::afterPropertiesSet).doesNotThrowAnyException();
	}

	@Test
	public void doFilter_test() throws IOException, ServletException {
		OptionsProvider optionsProvider = mock(OptionsProvider.class);
		AttestationOptions attestationOptions =
				new AttestationOptions(null, null, null, null, null, null, null, null, null);
		when(optionsProvider.getAttestationOptions(any(), any(), any())).thenReturn(attestationOptions);
		AttestationOptionsEndpointFilter attestationOptionsEndpointFilter = new AttestationOptionsEndpointFilter(optionsProvider, jsonConverter);
		MFATokenEvaluator mfaTokenEvaluator = new MFATokenEvaluatorImpl();
		AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
		attestationOptionsEndpointFilter.setMFATokenEvaluator(mfaTokenEvaluator);
		attestationOptionsEndpointFilter.setTrustResolver(trustResolver);

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestURI(FILTER_URL);
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain filterChain = new MockFilterChain();

		attestationOptionsEndpointFilter.doFilter(request, response, filterChain);
		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
	}

	@Test
	public void doFilter_with_error_test() throws IOException, ServletException {
		OptionsProvider optionsProvider = mock(OptionsProvider.class);
		doThrow(new RuntimeException()).when(optionsProvider).getAttestationOptions(any(), any(), any());
		AttestationOptionsEndpointFilter attestationOptionsEndpointFilter = new AttestationOptionsEndpointFilter(optionsProvider, jsonConverter);
		MFATokenEvaluator mfaTokenEvaluator = new MFATokenEvaluatorImpl();
		AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
		attestationOptionsEndpointFilter.setMFATokenEvaluator(mfaTokenEvaluator);
		attestationOptionsEndpointFilter.setTrustResolver(trustResolver);

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestURI(FILTER_URL);
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain filterChain = new MockFilterChain();

		attestationOptionsEndpointFilter.doFilter(request, response, filterChain);
		assertThat(response.getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR.value());
	}

	@Test
	public void writeErrorResponse_with_RuntimeException_test() throws IOException {
		OptionsProvider optionsProvider = mock(OptionsProvider.class);
		AttestationOptionsEndpointFilter attestationOptionsEndpointFilter = new AttestationOptionsEndpointFilter(optionsProvider, jsonConverter);

		MockHttpServletResponse response = new MockHttpServletResponse();
		RuntimeException exception = new RuntimeException();
		attestationOptionsEndpointFilter.writeErrorResponse(response, exception);
		assertThat(response.getContentAsString()).isEqualTo("{\"errorMessage\":\"The server encountered an internal error\"}");
	}

	@Test
	public void writeErrorResponse_with_InsufficientAuthenticationException_test() throws IOException {
		OptionsProvider optionsProvider = mock(OptionsProvider.class);
		AttestationOptionsEndpointFilter attestationOptionsEndpointFilter = new AttestationOptionsEndpointFilter(optionsProvider, jsonConverter);

		MockHttpServletResponse response = new MockHttpServletResponse();
		InsufficientAuthenticationException exception = new InsufficientAuthenticationException(null);
		attestationOptionsEndpointFilter.writeErrorResponse(response, exception);
		assertThat(response.getContentAsString()).isEqualTo("{\"errorMessage\":\"Anonymous access is prohibited\"}");
	}

}
