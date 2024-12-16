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

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.stubbing.Answer;
import org.skyscreamer.jsonassert.JSONAssert;

import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.api.TestPublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.management.WebAuthnRelyingPartyOperations;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.verifyNoInteractions;
import static org.mockito.BDDMockito.willAnswer;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link PublicKeyCredentialRequestOptionsFilter}.
 *
 * @author Rob Winch
 * @since 6.4
 */
@ExtendWith(MockitoExtension.class)
class PublicKeyCredentialRequestOptionsFilterTests {

	@Mock
	private WebAuthnRelyingPartyOperations relyingPartyOperations;

	@Mock
	private PublicKeyCredentialRequestOptionsRepository requestOptionsRepository;

	@Mock
	private HttpMessageConverter<Object> converter;

	@Mock
	private SecurityContextHolderStrategy contextHolderStrategy;

	private PublicKeyCredentialRequestOptionsFilter filter;

	private MockMvc mockMvc;

	@BeforeEach
	void setup() {
		this.filter = new PublicKeyCredentialRequestOptionsFilter(this.relyingPartyOperations);
		this.filter.setRequestOptionsRepository(this.requestOptionsRepository);
		this.mockMvc = MockMvcBuilders.standaloneSetup().addFilter(this.filter).build();
	}

	@AfterEach
	void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test
	void constructorWhenNull() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> new PublicKeyCredentialRequestOptionsFilter(null));
	}

	@Test
	void doFilterWhenNoMatch() throws Exception {
		this.mockMvc.perform(post("/nomatch"))
			.andExpect(status().isNotFound())
			.andDo((result) -> assertThat(result.getResponse().getContentAsString()).isEmpty());
		verifyNoInteractions(this.relyingPartyOperations, this.requestOptionsRepository);
	}

	@Test
	void doFilterWhenNotPost() throws Exception {
		this.mockMvc.perform(get("/webauthn/authenticate/options"))
			.andExpect(status().isNotFound())
			.andDo((result) -> assertThat(result.getResponse().getContentAsString()).isEmpty());
		verifyNoInteractions(this.relyingPartyOperations, this.requestOptionsRepository);
	}

	@Test
	void doFilterWhenMatches() throws Exception {
		PublicKeyCredentialRequestOptions options = TestPublicKeyCredentialRequestOptions.create().build();
		given(this.relyingPartyOperations.createCredentialRequestOptions(any())).willReturn(options);

		PublicKeyCredentialCreationOptions mockResult = this.relyingPartyOperations
			.createPublicKeyCredentialCreationOptions(null);
		this.mockMvc.perform(post("/webauthn/authenticate/options"))
			.andExpect(status().isOk())
			.andDo((result) -> JSONAssert.assertEquals(result.getResponse().getContentAsString(), """
					{
						"challenge": "cQfdGrj9zDg3zNBkOH3WPL954FTOShVy0-CoNgSewNM",
						"timeout": 300000,
						"rpId": "example.localhost",
						"allowCredentials": [],
						"userVerification": "preferred",
						"extensions": {}
					}
					""", false));
	}

	@Test
	void doFilterWhenCustom() throws Exception {
		String body = "custom body";
		willAnswer(new Answer<Void>() {
			@Override
			public Void answer(InvocationOnMock invocation) throws Throwable {
				ServletServerHttpResponse response = invocation.getArgument(2);
				response.getBody().write(body.getBytes(StandardCharsets.UTF_8));
				return null;
			}
		}).given(this.converter).write(any(), any(), any());
		given(this.contextHolderStrategy.getContext())
			.willReturn(new SecurityContextImpl(new TestingAuthenticationToken("user", "password", "ROLE_USER")));
		this.filter.setConverter(this.converter);
		this.filter.setSecurityContextHolderStrategy(this.contextHolderStrategy);
		PublicKeyCredentialRequestOptions options = TestPublicKeyCredentialRequestOptions.create().build();
		given(this.relyingPartyOperations.createCredentialRequestOptions(any())).willReturn(options);

		PublicKeyCredentialCreationOptions mockResult = this.relyingPartyOperations
			.createPublicKeyCredentialCreationOptions(null);
		this.mockMvc.perform(post("/webauthn/authenticate/options"))
			.andExpect(status().isOk())
			.andDo((result) -> assertThat(result.getResponse().getContentAsString()).isEqualTo(body));
	}

	@Test
	void setConverterWhenNull() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setConverter(null));
	}

	@Test
	void setSecurityContextHolderStrategyWhenNull() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setSecurityContextHolderStrategy(null));
	}

}
