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

package org.springframework.security.web.webauthn.registration;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.skyscreamer.jsonassert.JSONAssert;

import org.springframework.http.HttpStatus;
import org.springframework.http.converter.GenericHttpMessageConverter;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.web.webauthn.api.ImmutableCredentialRecord;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.api.TestCredentialRecord;
import org.springframework.security.web.webauthn.api.TestPublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import org.springframework.security.web.webauthn.management.WebAuthnRelyingPartyOperations;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Tests for {@link WebAuthnRegistrationFilter}.
 *
 * @author Rob Winch
 * @since 6.4
 */
@ExtendWith(MockitoExtension.class)
class WebAuthnRegistrationFilterTests {

	@Mock
	private UserCredentialRepository userCredentials;

	@Mock
	private WebAuthnRelyingPartyOperations operations;

	@Mock
	private GenericHttpMessageConverter<Object> converter;

	@Mock
	private PublicKeyCredentialCreationOptionsRepository creationOptionsRepository;

	@Mock
	private FilterChain chain;

	private MockHttpServletResponse response = new MockHttpServletResponse();

	private static final String REGISTRATION_REQUEST_BODY = """
			{
				"publicKey": {
					"credential": {
						"id": "dYF7EGnRFFIXkpXi9XU2wg",
						"rawId": "dYF7EGnRFFIXkpXi9XU2wg",
						"response": {
							"attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViUy9GqwTRaMpzVDbXq1dyEAXVOxrou08k22ggRC45MKNhdAAAAALraVWanqkAfvZZFYZpVEg0AEHWBexBp0RRSF5KV4vV1NsKlAQIDJiABIVggQjmrekPGzyqtoKK9HPUH-8Z2FLpoqkklFpFPQVICQ3IiWCD6I9Jvmor685fOZOyGXqUd87tXfvJk8rxj9OhuZvUALA",
							"clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiSl9RTi10SFJYRWVKYjlNcUNrWmFPLUdOVmlibXpGVGVWMk43Z0ptQUdrQSIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5sb2NhbGhvc3Q6ODQ0MyIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
							"transports": [
								"internal",
								"hybrid"
							]
						},
						"type": "public-key",
						"clientExtensionResults": {},
						"authenticatorAttachment": "platform"
					},
					"label": "1password"
				}
			}
			""";

	private WebAuthnRegistrationFilter filter;

	@BeforeEach
	void setup() {
		this.filter = new WebAuthnRegistrationFilter(this.userCredentials, this.operations);
	}

	@Test
	void constructorWhenNullUserCredentials() {
		assertThatIllegalArgumentException().isThrownBy(() -> new WebAuthnRegistrationFilter(null, this.operations));
	}

	@Test
	void constructorWhenNullOperations() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new WebAuthnRegistrationFilter(this.userCredentials, null));
	}

	@Test
	void doFilterWhenRegisterUrlDoesNotMatchThenChainContinues() throws Exception {
		HttpServletResponse response = mock(HttpServletResponse.class);
		this.filter.setConverter(this.converter);
		this.filter.setCreationOptionsRepository(this.creationOptionsRepository);
		this.filter.doFilter(post("/nomatch").buildRequest(new MockServletContext()), response, this.chain);
		verifyNoInteractions(this.converter, this.creationOptionsRepository, response);
		verify(this.chain).doFilter(any(), any());
	}

	@Test
	void doFilterWhenRegisterMethodDoesNotMatchThenChainContinues() throws Exception {
		HttpServletResponse response = mock(HttpServletResponse.class);
		this.filter.setConverter(this.converter);
		this.filter.setCreationOptionsRepository(this.creationOptionsRepository);
		this.filter.doFilter(
				get(WebAuthnRegistrationFilter.DEFAULT_REGISTER_CREDENTIAL_URL).buildRequest(new MockServletContext()),
				response, this.chain);
		verifyNoInteractions(this.converter, this.creationOptionsRepository, response);
		verify(this.chain).doFilter(any(), any());
	}

	@Test
	void doFilterWhenRegisterNoBodyThenBadRequest() throws Exception {
		this.filter.doFilter(registerCredentialRequest(""), this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
	}

	@Test
	void doFilterWhenInvalidJsonThenBadRequest() throws Exception {
		this.filter.doFilter(registerCredentialRequest("{"), this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
	}

	@Test
	void doFilterWhenRegisterOptionsNullThenBadRequest() throws Exception {
		this.filter.setCreationOptionsRepository(this.creationOptionsRepository);
		MockHttpServletRequest request = registerCredentialRequest(REGISTRATION_REQUEST_BODY);
		this.filter.doFilter(request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
	}

	@Test
	void doFilterWhenRegisterSuccessThenOk() throws Exception {
		this.filter.setCreationOptionsRepository(this.creationOptionsRepository);
		PublicKeyCredentialCreationOptions creationOptions = TestPublicKeyCredentialCreationOptions
			.createPublicKeyCredentialCreationOptions()
			.build();
		given(this.creationOptionsRepository.load(any())).willReturn(creationOptions);
		ImmutableCredentialRecord userCredential = TestCredentialRecord.userCredential().build();
		given(this.operations.registerCredential(any())).willReturn(userCredential);
		MockHttpServletRequest request = registerCredentialRequest(REGISTRATION_REQUEST_BODY);
		this.filter.doFilter(request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpStatus.OK.value());
		String actualBody = this.response.getContentAsString();
		String expectedBody = """
				{
					"success": true
				}
				""";
		JSONAssert.assertEquals(expectedBody, actualBody, false);
		verify(this.creationOptionsRepository).save(any(), any(), eq(null));
	}

	@Test
	void doFilterWhenDeleteSuccessThenNoContent() throws Exception {
		MockHttpServletRequest request = MockMvcRequestBuilders.delete("/webauthn/register/123456")
			.buildRequest(new MockServletContext());
		this.filter.doFilter(request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpStatus.NO_CONTENT.value());
	}

	private static MockHttpServletRequest registerCredentialRequest(String body) {
		return MockMvcRequestBuilders.post(WebAuthnRegistrationFilter.DEFAULT_REGISTER_CREDENTIAL_URL)
			.content(body)
			.buildRequest(new MockServletContext());
	}

}
