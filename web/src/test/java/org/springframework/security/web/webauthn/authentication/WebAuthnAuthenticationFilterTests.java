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

package org.springframework.security.web.webauthn.authentication;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.skyscreamer.jsonassert.JSONAssert;

import org.springframework.http.HttpStatus;
import org.springframework.http.converter.GenericHttpMessageConverter;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.webauthn.api.AuthenticatorAssertionResponse;
import org.springframework.security.web.webauthn.api.AuthenticatorAttachment;
import org.springframework.security.web.webauthn.api.PublicKeyCredential;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.TestPublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.api.TestPublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.management.RelyingPartyAuthenticationRequest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Tests for {@link WebAuthnAuthenticationFilter}.
 *
 * @author Rob Winch
 * @since 6.4
 */
@ExtendWith(MockitoExtension.class)
class WebAuthnAuthenticationFilterTests {

	private static final String VALID_BODY = """
				{
					"id": "dYF7EGnRFFIXkpXi9XU2wg",
					"rawId": "dYF7EGnRFFIXkpXi9XU2wg",
					"response": {
						"authenticatorData": "y9GqwTRaMpzVDbXq1dyEAXVOxrou08k22ggRC45MKNgdAAAAAA",
						"clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiRFVsRzRDbU9naWhKMG1vdXZFcE9HdUk0ZVJ6MGRRWmxUQmFtbjdHQ1FTNCIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5sb2NhbGhvc3Q6ODQ0MyIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
						"signature": "MEYCIQCW2BcUkRCAXDmGxwMi78jknenZ7_amWrUJEYoTkweldAIhAMD0EMp1rw2GfwhdrsFIeDsL7tfOXVPwOtfqJntjAo4z",
						"userHandle": "Q3_0Xd64_HW0BlKRAJnVagJTpLKLgARCj8zjugpRnVo"
					},
					"clientExtensionResults": {},
					"authenticatorAttachment": "platform"
				}
			""";

	@Mock
	private GenericHttpMessageConverter<Object> converter;

	@Mock
	private PublicKeyCredentialRequestOptionsRepository requestOptionsRepository;

	@Mock
	private AuthenticationManager authenticationManager;

	private MockHttpServletResponse response = new MockHttpServletResponse();

	@Mock
	private FilterChain chain;

	private WebAuthnAuthenticationFilter filter = new WebAuthnAuthenticationFilter();

	@BeforeEach
	void setup() {
		this.filter.setAuthenticationManager(this.authenticationManager);
	}

	@Test
	void setConverterWhenNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setConverter(null));
	}

	@Test
	void setRequestOptionsRepositoryWhenNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setRequestOptionsRepository(null));
	}

	@Test
	void doFilterWhenUrlDoesNotMatchThenChainContinues() throws Exception {
		HttpServletResponse response = mock(HttpServletResponse.class);
		this.filter.setConverter(this.converter);
		this.filter.setRequestOptionsRepository(this.requestOptionsRepository);
		this.filter.doFilter(post("/nomatch").buildRequest(new MockServletContext()), response, this.chain);
		verifyNoInteractions(this.converter, this.requestOptionsRepository, response);
		verify(this.chain).doFilter(any(), any());
	}

	@Test
	void doFilterWhenMethodDoesNotMatchThenChainContinues() throws Exception {
		HttpServletResponse response = mock(HttpServletResponse.class);
		this.filter.setConverter(this.converter);
		this.filter.setRequestOptionsRepository(this.requestOptionsRepository);
		this.filter.doFilter(get("/login/webauthn").buildRequest(new MockServletContext()), response, this.chain);
		verifyNoInteractions(this.converter, this.requestOptionsRepository, response);
		verify(this.chain).doFilter(any(), any());
	}

	@Test
	void doFilterWhenNoBodyThenUnauthorized() throws Exception {
		this.filter.doFilter(matchingRequest(""), this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
	}

	@Test
	void doFilterWhenInvalidJsonThenUnauthorized() throws Exception {
		MockHttpServletRequest request = matchingRequest("<>");
		this.filter.doFilter(request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
	}

	@Test
	void doFilterWhenOptionsNullThenUnAuthorized() throws Exception {
		MockHttpServletRequest request = matchingRequest(VALID_BODY);
		this.filter.doFilter(request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
	}

	@Test
	void doFilterWhenValidThenOk() throws Exception {
		PublicKeyCredentialRequestOptions options = TestPublicKeyCredentialRequestOptions.create().build();
		given(this.requestOptionsRepository.load(any())).willReturn(options);
		PublicKeyCredentialUserEntity principal = TestPublicKeyCredentialUserEntity.userEntity().build();
		WebAuthnAuthentication authentication = new WebAuthnAuthentication(principal,
				AuthorityUtils.createAuthorityList("ROLE_USER"));
		given(this.authenticationManager.authenticate(any())).willReturn(authentication);
		this.filter.setRequestOptionsRepository(this.requestOptionsRepository);
		MockHttpServletRequest request = matchingRequest(VALID_BODY);
		this.filter.doFilter(request, this.response, this.chain);
		verify(this.requestOptionsRepository).save(any(), any(), isNull());
		ArgumentCaptor<WebAuthnAuthenticationRequestToken> authenticationCaptor = ArgumentCaptor
			.forClass(WebAuthnAuthenticationRequestToken.class);
		verify(this.authenticationManager).authenticate(authenticationCaptor.capture());
		assertThat(this.response.getStatus()).isEqualTo(HttpStatus.OK.value());
		WebAuthnAuthenticationRequestToken token = authenticationCaptor.getValue();
		assertThat(token).isNotNull();
		RelyingPartyAuthenticationRequest authnRequest = token.getWebAuthnRequest();
		PublicKeyCredential<AuthenticatorAssertionResponse> publicKey = authnRequest.getPublicKey();
		AuthenticatorAssertionResponse assertionResponse = publicKey.getResponse();
		assertThat(publicKey.getId()).isEqualTo("dYF7EGnRFFIXkpXi9XU2wg");
		assertThat(publicKey.getRawId().toBase64UrlString()).isEqualTo("dYF7EGnRFFIXkpXi9XU2wg");
		assertThat(assertionResponse.getAuthenticatorData().toBase64UrlString())
			.isEqualTo("y9GqwTRaMpzVDbXq1dyEAXVOxrou08k22ggRC45MKNgdAAAAAA");
		assertThat(assertionResponse.getClientDataJSON().toBase64UrlString()).isEqualTo(
				"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiRFVsRzRDbU9naWhKMG1vdXZFcE9HdUk0ZVJ6MGRRWmxUQmFtbjdHQ1FTNCIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5sb2NhbGhvc3Q6ODQ0MyIsImNyb3NzT3JpZ2luIjpmYWxzZX0");
		assertThat(assertionResponse.getSignature().toBase64UrlString()).isEqualTo(
				"MEYCIQCW2BcUkRCAXDmGxwMi78jknenZ7_amWrUJEYoTkweldAIhAMD0EMp1rw2GfwhdrsFIeDsL7tfOXVPwOtfqJntjAo4z");
		assertThat(assertionResponse.getUserHandle().toBase64UrlString())
			.isEqualTo("Q3_0Xd64_HW0BlKRAJnVagJTpLKLgARCj8zjugpRnVo");
		assertThat(publicKey.getClientExtensionResults().getOutputs()).isEmpty();
		assertThat(authnRequest.getRequestOptions()).isEqualTo(options);
		assertThat(authnRequest.getPublicKey().getAuthenticatorAttachment())
			.isEqualTo(AuthenticatorAttachment.PLATFORM);
		String expectedBody = """
				{"redirectUrl":"/","authenticated":true}
				""";
		JSONAssert.assertEquals(expectedBody, this.response.getContentAsString(), false);
	}

	private static MockHttpServletRequest matchingRequest(String body) {
		return MockMvcRequestBuilders.post("/login/webauthn").content(body).buildRequest(new MockServletContext());
	}

}
