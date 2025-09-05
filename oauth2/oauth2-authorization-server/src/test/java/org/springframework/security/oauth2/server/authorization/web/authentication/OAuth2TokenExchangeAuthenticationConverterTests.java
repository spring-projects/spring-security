/*
 * Copyright 2020-2024 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.web.authentication;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link OAuth2TokenExchangeAuthenticationConverter}.
 *
 * @author Steve Riesenberg
 */
public class OAuth2TokenExchangeAuthenticationConverterTests {

	private static final String CLIENT_ID = "client-1";

	private static final String TOKEN_URI = "/oauth2/token";

	private static final String SUBJECT_TOKEN = "EfYu_0jEL";

	private static final String ACTOR_TOKEN = "JlNE_xR1f";

	private static final String ACCESS_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:access_token";

	private static final String JWT_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:jwt";

	private OAuth2TokenExchangeAuthenticationConverter converter;

	@BeforeEach
	public void setUp() {
		this.converter = new OAuth2TokenExchangeAuthenticationConverter();
	}

	@AfterEach
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void convertWhenMissingGrantTypeThenReturnNull() {
		MockHttpServletRequest request = createRequest();
		Authentication authentication = this.converter.convert(request);
		assertThat(authentication).isNull();
	}

	@Test
	public void convertWhenInvalidResourceThenInvalidRequestError() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.TOKEN_EXCHANGE.getValue());
		request.addParameter(OAuth2ParameterNames.RESOURCE, "invalid");
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.converter.convert(request))
				.withMessageContaining(OAuth2ParameterNames.RESOURCE)
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
		// @formatter:on
	}

	@Test
	public void convertWhenResourceContainsFragmentThenInvalidRequestError() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.TOKEN_EXCHANGE.getValue());
		request.addParameter(OAuth2ParameterNames.RESOURCE, "https://mydomain.com/#fragment");
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.converter.convert(request))
				.withMessageContaining(OAuth2ParameterNames.RESOURCE)
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
		// @formatter:on
	}

	@Test
	public void convertWhenMultipleScopeParametersThenInvalidRequestError() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.TOKEN_EXCHANGE.getValue());
		request.addParameter(OAuth2ParameterNames.SCOPE, "one");
		request.addParameter(OAuth2ParameterNames.SCOPE, "two");
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.converter.convert(request))
				.withMessageContaining(OAuth2ParameterNames.SCOPE)
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
		// @formatter:on
	}

	@Test
	public void convertWhenMultipleRequestedTokenTypeParametersThenInvalidRequestError() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.TOKEN_EXCHANGE.getValue());
		request.addParameter(OAuth2ParameterNames.REQUESTED_TOKEN_TYPE, ACCESS_TOKEN_TYPE_VALUE);
		request.addParameter(OAuth2ParameterNames.REQUESTED_TOKEN_TYPE, JWT_TOKEN_TYPE_VALUE);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.converter.convert(request))
				.withMessageContaining(OAuth2ParameterNames.REQUESTED_TOKEN_TYPE)
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
		// @formatter:on
	}

	@Test
	public void convertWhenInvalidRequestedTokenTypeThenUnsupportedTokenTypeError() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.TOKEN_EXCHANGE.getValue());
		request.addParameter(OAuth2ParameterNames.REQUESTED_TOKEN_TYPE, "invalid");
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.converter.convert(request))
				.withMessageContaining(OAuth2ParameterNames.REQUESTED_TOKEN_TYPE)
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.UNSUPPORTED_TOKEN_TYPE);
		// @formatter:on
	}

	@Test
	public void convertWhenMissingSubjectTokenThenInvalidRequestError() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.TOKEN_EXCHANGE.getValue());
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.converter.convert(request))
				.withMessageContaining(OAuth2ParameterNames.SUBJECT_TOKEN)
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
		// @formatter:on
	}

	@Test
	public void convertWhenMultipleSubjectTokenParametersThenInvalidRequestError() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.TOKEN_EXCHANGE.getValue());
		request.addParameter(OAuth2ParameterNames.SUBJECT_TOKEN, SUBJECT_TOKEN);
		request.addParameter(OAuth2ParameterNames.SUBJECT_TOKEN, "another");
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.converter.convert(request))
				.withMessageContaining(OAuth2ParameterNames.SUBJECT_TOKEN)
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
		// @formatter:on
	}

	@Test
	public void convertWhenMissingSubjectTokenTypeThenInvalidRequestError() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.TOKEN_EXCHANGE.getValue());
		request.addParameter(OAuth2ParameterNames.SUBJECT_TOKEN, SUBJECT_TOKEN);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.converter.convert(request))
				.withMessageContaining(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE)
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
		// @formatter:on
	}

	@Test
	public void convertWhenMultipleSubjectTokenTypeParametersThenInvalidRequestError() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.TOKEN_EXCHANGE.getValue());
		request.addParameter(OAuth2ParameterNames.SUBJECT_TOKEN, SUBJECT_TOKEN);
		request.addParameter(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE, ACCESS_TOKEN_TYPE_VALUE);
		request.addParameter(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE, JWT_TOKEN_TYPE_VALUE);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.converter.convert(request))
				.withMessageContaining(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE)
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
		// @formatter:on
	}

	@Test
	public void convertWhenInvalidSubjectTokenTypeThenUnsupportedTokenTypeError() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.TOKEN_EXCHANGE.getValue());
		request.addParameter(OAuth2ParameterNames.SUBJECT_TOKEN, SUBJECT_TOKEN);
		request.addParameter(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE, "invalid");
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.converter.convert(request))
				.withMessageContaining(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE)
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.UNSUPPORTED_TOKEN_TYPE);
		// @formatter:on
	}

	@Test
	public void convertWhenMultipleActorTokenParametersThenInvalidRequestError() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.TOKEN_EXCHANGE.getValue());
		request.addParameter(OAuth2ParameterNames.SUBJECT_TOKEN, SUBJECT_TOKEN);
		request.addParameter(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE, ACCESS_TOKEN_TYPE_VALUE);
		request.addParameter(OAuth2ParameterNames.ACTOR_TOKEN, ACTOR_TOKEN);
		request.addParameter(OAuth2ParameterNames.ACTOR_TOKEN, "another");
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.converter.convert(request))
				.withMessageContaining(OAuth2ParameterNames.ACTOR_TOKEN)
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
		// @formatter:on
	}

	@Test
	public void convertWhenActorTokenAndMissingActorTokenTypeThenInvalidRequestError() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.TOKEN_EXCHANGE.getValue());
		request.addParameter(OAuth2ParameterNames.SUBJECT_TOKEN, SUBJECT_TOKEN);
		request.addParameter(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE, ACCESS_TOKEN_TYPE_VALUE);
		request.addParameter(OAuth2ParameterNames.ACTOR_TOKEN, ACTOR_TOKEN);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.converter.convert(request))
				.withMessageContaining(OAuth2ParameterNames.ACTOR_TOKEN_TYPE)
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
		// @formatter:on
	}

	@Test
	public void convertWhenActorTokenTypeAndMissingActorTokenThenInvalidRequestError() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.TOKEN_EXCHANGE.getValue());
		request.addParameter(OAuth2ParameterNames.SUBJECT_TOKEN, SUBJECT_TOKEN);
		request.addParameter(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE, ACCESS_TOKEN_TYPE_VALUE);
		request.addParameter(OAuth2ParameterNames.ACTOR_TOKEN_TYPE, JWT_TOKEN_TYPE_VALUE);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.converter.convert(request))
				.withMessageContaining(OAuth2ParameterNames.ACTOR_TOKEN)
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
		// @formatter:on
	}

	@Test
	public void convertWhenInvalidActorTokenTypeThenUnsupportedTokenTypeError() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.TOKEN_EXCHANGE.getValue());
		request.addParameter(OAuth2ParameterNames.SUBJECT_TOKEN, SUBJECT_TOKEN);
		request.addParameter(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE, ACCESS_TOKEN_TYPE_VALUE);
		request.addParameter(OAuth2ParameterNames.ACTOR_TOKEN, ACTOR_TOKEN);
		request.addParameter(OAuth2ParameterNames.ACTOR_TOKEN_TYPE, "invalid");
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.converter.convert(request))
				.withMessageContaining(OAuth2ParameterNames.ACTOR_TOKEN_TYPE)
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.UNSUPPORTED_TOKEN_TYPE);
		// @formatter:on
	}

	@Test
	public void convertWhenAllParametersThenTokenExchangeAuthenticationToken() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.TOKEN_EXCHANGE.getValue());
		request.addParameter(OAuth2ParameterNames.RESOURCE, "https://mydomain.com/resource1");
		request.addParameter(OAuth2ParameterNames.RESOURCE, "https://mydomain.com/resource2");
		request.addParameter(OAuth2ParameterNames.AUDIENCE, "audience1");
		request.addParameter(OAuth2ParameterNames.AUDIENCE, "audience2");
		request.addParameter(OAuth2ParameterNames.SCOPE, "one two");
		request.addParameter(OAuth2ParameterNames.REQUESTED_TOKEN_TYPE, JWT_TOKEN_TYPE_VALUE);
		request.addParameter(OAuth2ParameterNames.SUBJECT_TOKEN, SUBJECT_TOKEN);
		request.addParameter(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE, ACCESS_TOKEN_TYPE_VALUE);
		request.addParameter(OAuth2ParameterNames.ACTOR_TOKEN, ACTOR_TOKEN);
		request.addParameter(OAuth2ParameterNames.ACTOR_TOKEN_TYPE, JWT_TOKEN_TYPE_VALUE);

		SecurityContextImpl securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(new TestingAuthenticationToken(CLIENT_ID, null));
		SecurityContextHolder.setContext(securityContext);

		OAuth2TokenExchangeAuthenticationToken authentication = (OAuth2TokenExchangeAuthenticationToken) this.converter
			.convert(request);
		assertThat(authentication).isNotNull();
		assertThat(authentication.getResources()).containsExactly("https://mydomain.com/resource1",
				"https://mydomain.com/resource2");
		assertThat(authentication.getAudiences()).containsExactly("audience1", "audience2");
		assertThat(authentication.getScopes()).containsExactly("one", "two");
		assertThat(authentication.getRequestedTokenType()).isEqualTo(JWT_TOKEN_TYPE_VALUE);
		assertThat(authentication.getSubjectToken()).isEqualTo(SUBJECT_TOKEN);
		assertThat(authentication.getSubjectTokenType()).isEqualTo(ACCESS_TOKEN_TYPE_VALUE);
		assertThat(authentication.getActorToken()).isEqualTo(ACTOR_TOKEN);
		assertThat(authentication.getActorTokenType()).isEqualTo(JWT_TOKEN_TYPE_VALUE);
	}

	private static MockHttpServletRequest createRequest() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setMethod(HttpMethod.POST.name());
		request.setRequestURI(TOKEN_URI);
		return request;
	}

}
