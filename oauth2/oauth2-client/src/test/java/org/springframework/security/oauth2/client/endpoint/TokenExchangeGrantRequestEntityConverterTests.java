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

package org.springframework.security.oauth2.client.endpoint;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jwt.TestJwts;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link TokenExchangeGrantRequestEntityConverter}.
 *
 * @author Steve Riesenberg
 */
public class TokenExchangeGrantRequestEntityConverterTests {

	private static final String ACCESS_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:access_token";

	private static final String JWT_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:jwt";

	private TokenExchangeGrantRequestEntityConverter converter;

	private OAuth2Token subjectToken;

	private OAuth2Token actorToken;

	@BeforeEach
	public void setUp() {
		this.converter = new TokenExchangeGrantRequestEntityConverter();
		this.subjectToken = TestOAuth2AccessTokens.scopes("read", "write");
		this.actorToken = null;
	}

	@Test
	public void setHeadersConverterWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.converter.setHeadersConverter(null))
				.withMessage("headersConverter cannot be null");
		// @formatter:on
	}

	@Test
	public void addHeadersConverterWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.converter.addHeadersConverter(null))
				.withMessage("headersConverter cannot be null");
		// @formatter:on
	}

	@Test
	public void setParametersConverterWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.converter.setParametersConverter(null))
				.withMessage("parametersConverter cannot be null");
		// @formatter:on
	}

	@Test
	public void addParametersConverterWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.converter.addParametersConverter(null))
				.withMessage("parametersConverter cannot be null");
		// @formatter:on
	}

	@Test
	public void convertWhenHeadersConverterSetThenCalled() {
		Converter<TokenExchangeGrantRequest, HttpHeaders> headersConverter1 = mock(Converter.class);
		this.converter.setHeadersConverter(headersConverter1);
		Converter<TokenExchangeGrantRequest, HttpHeaders> headersConverter2 = mock(Converter.class);
		this.converter.addHeadersConverter(headersConverter2);
		// @formatter:off
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration()
				.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
				.scope("read", "write")
				.build();
		// @formatter:on
		TokenExchangeGrantRequest grantRequest = new TokenExchangeGrantRequest(clientRegistration, this.subjectToken,
				this.actorToken);
		this.converter.convert(grantRequest);
		InOrder inOrder = inOrder(headersConverter1, headersConverter2);
		inOrder.verify(headersConverter1).convert(grantRequest);
		inOrder.verify(headersConverter2).convert(grantRequest);
	}

	@Test
	public void convertWhenParametersConverterSetThenCalled() {
		Converter<TokenExchangeGrantRequest, MultiValueMap<String, String>> parametersConverter1 = mock(
				Converter.class);
		this.converter.setParametersConverter(parametersConverter1);
		Converter<TokenExchangeGrantRequest, MultiValueMap<String, String>> parametersConverter2 = mock(
				Converter.class);
		this.converter.addParametersConverter(parametersConverter2);
		// @formatter:off
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration()
				.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
				.scope("read", "write")
				.build();
		// @formatter:on
		TokenExchangeGrantRequest grantRequest = new TokenExchangeGrantRequest(clientRegistration, this.subjectToken,
				this.actorToken);
		this.converter.convert(grantRequest);
		InOrder inOrder = inOrder(parametersConverter1, parametersConverter2);
		inOrder.verify(parametersConverter1).convert(any(TokenExchangeGrantRequest.class));
		inOrder.verify(parametersConverter2).convert(any(TokenExchangeGrantRequest.class));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void convertWhenGrantRequestValidThenConverts() {
		// @formatter:off
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration()
				.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
				.scope("read", "write")
				.build();
		// @formatter:on
		TokenExchangeGrantRequest grantRequest = new TokenExchangeGrantRequest(clientRegistration, this.subjectToken,
				this.actorToken);
		RequestEntity<?> requestEntity = this.converter.convert(grantRequest);
		assertThat(requestEntity).isNotNull();
		assertThat(requestEntity.getMethod()).isEqualTo(HttpMethod.POST);
		assertThat(requestEntity.getUrl().toASCIIString())
			.isEqualTo(clientRegistration.getProviderDetails().getTokenUri());
		HttpHeaders headers = requestEntity.getHeaders();
		assertThat(headers.getAccept())
			.contains(MediaType.valueOf(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8"));
		assertThat(headers.getContentType())
			.isEqualTo(MediaType.valueOf(MediaType.APPLICATION_FORM_URLENCODED_VALUE + ";charset=UTF-8"));
		assertThat(headers.getFirst(HttpHeaders.AUTHORIZATION)).startsWith("Basic ");
		MultiValueMap<String, String> formParameters = (MultiValueMap<String, String>) requestEntity.getBody();
		assertThat(formParameters).isNotNull();
		assertThat(formParameters.getFirst(OAuth2ParameterNames.GRANT_TYPE))
			.isEqualTo(AuthorizationGrantType.TOKEN_EXCHANGE.getValue());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.REQUESTED_TOKEN_TYPE))
			.isEqualTo(ACCESS_TOKEN_TYPE_VALUE);
		assertThat(formParameters.getFirst(OAuth2ParameterNames.SUBJECT_TOKEN))
			.isEqualTo(this.subjectToken.getTokenValue());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE)).isEqualTo(ACCESS_TOKEN_TYPE_VALUE);
		assertThat(formParameters.getFirst(OAuth2ParameterNames.SCOPE))
			.isEqualTo(StringUtils.collectionToDelimitedString(clientRegistration.getScopes(), " "));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void convertWhenClientAuthenticationMethodIsClientSecretPostThenClientIdAndSecretParametersPresent() {
		// @formatter:off
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration()
				.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
				.scope("read", "write")
				.build();
		// @formatter:on
		TokenExchangeGrantRequest grantRequest = new TokenExchangeGrantRequest(clientRegistration, this.subjectToken,
				this.actorToken);
		RequestEntity<?> requestEntity = this.converter.convert(grantRequest);
		assertThat(requestEntity).isNotNull();
		assertThat(requestEntity.getMethod()).isEqualTo(HttpMethod.POST);
		assertThat(requestEntity.getUrl().toASCIIString())
			.isEqualTo(clientRegistration.getProviderDetails().getTokenUri());
		HttpHeaders headers = requestEntity.getHeaders();
		assertThat(headers.getAccept())
			.contains(MediaType.valueOf(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8"));
		assertThat(headers.getContentType())
			.isEqualTo(MediaType.valueOf(MediaType.APPLICATION_FORM_URLENCODED_VALUE + ";charset=UTF-8"));
		assertThat(headers.getFirst(HttpHeaders.AUTHORIZATION)).isNull();
		MultiValueMap<String, String> formParameters = (MultiValueMap<String, String>) requestEntity.getBody();
		assertThat(formParameters).isNotNull();
		assertThat(formParameters.getFirst(OAuth2ParameterNames.GRANT_TYPE))
			.isEqualTo(AuthorizationGrantType.TOKEN_EXCHANGE.getValue());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.REQUESTED_TOKEN_TYPE))
			.isEqualTo(ACCESS_TOKEN_TYPE_VALUE);
		assertThat(formParameters.getFirst(OAuth2ParameterNames.SUBJECT_TOKEN))
			.isEqualTo(this.subjectToken.getTokenValue());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE)).isEqualTo(ACCESS_TOKEN_TYPE_VALUE);
		assertThat(formParameters.getFirst(OAuth2ParameterNames.SCOPE))
			.isEqualTo(StringUtils.collectionToDelimitedString(clientRegistration.getScopes(), " "));
		assertThat(formParameters.getFirst(OAuth2ParameterNames.CLIENT_ID)).isEqualTo(clientRegistration.getClientId());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.CLIENT_SECRET))
			.isEqualTo(clientRegistration.getClientSecret());
	}

	@SuppressWarnings("unchecked")
	@Test
	public void convertWhenActorTokenIsNotNullThenActorTokenParametersPresent() {
		// @formatter:off
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration()
				.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
				.scope("read", "write")
				.build();
		// @formatter:on
		this.actorToken = TestOAuth2AccessTokens.noScopes();
		TokenExchangeGrantRequest grantRequest = new TokenExchangeGrantRequest(clientRegistration, this.subjectToken,
				this.actorToken);
		RequestEntity<?> requestEntity = this.converter.convert(grantRequest);
		assertThat(requestEntity).isNotNull();
		MultiValueMap<String, String> formParameters = (MultiValueMap<String, String>) requestEntity.getBody();
		assertThat(formParameters).isNotNull();
		assertThat(formParameters.getFirst(OAuth2ParameterNames.GRANT_TYPE))
			.isEqualTo(AuthorizationGrantType.TOKEN_EXCHANGE.getValue());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.REQUESTED_TOKEN_TYPE))
			.isEqualTo(ACCESS_TOKEN_TYPE_VALUE);
		assertThat(formParameters.getFirst(OAuth2ParameterNames.SUBJECT_TOKEN))
			.isEqualTo(this.subjectToken.getTokenValue());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE)).isEqualTo(ACCESS_TOKEN_TYPE_VALUE);
		assertThat(formParameters.getFirst(OAuth2ParameterNames.ACTOR_TOKEN))
			.isEqualTo(this.actorToken.getTokenValue());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.ACTOR_TOKEN_TYPE)).isEqualTo(ACCESS_TOKEN_TYPE_VALUE);
		assertThat(formParameters.getFirst(OAuth2ParameterNames.SCOPE))
			.isEqualTo(StringUtils.collectionToDelimitedString(clientRegistration.getScopes(), " "));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void convertWhenSubjectTokenIsJwtThenSubjectTokenTypeIsJwt() {
		// @formatter:off
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration()
				.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
				.scope("read", "write")
				.build();
		// @formatter:on
		this.subjectToken = TestJwts.jwt().build();
		TokenExchangeGrantRequest grantRequest = new TokenExchangeGrantRequest(clientRegistration, this.subjectToken,
				this.actorToken);
		RequestEntity<?> requestEntity = this.converter.convert(grantRequest);
		assertThat(requestEntity).isNotNull();
		MultiValueMap<String, String> formParameters = (MultiValueMap<String, String>) requestEntity.getBody();
		assertThat(formParameters).isNotNull();
		assertThat(formParameters.getFirst(OAuth2ParameterNames.GRANT_TYPE))
			.isEqualTo(AuthorizationGrantType.TOKEN_EXCHANGE.getValue());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.REQUESTED_TOKEN_TYPE))
			.isEqualTo(ACCESS_TOKEN_TYPE_VALUE);
		assertThat(formParameters.getFirst(OAuth2ParameterNames.SUBJECT_TOKEN))
			.isEqualTo(this.subjectToken.getTokenValue());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE)).isEqualTo(JWT_TOKEN_TYPE_VALUE);
		assertThat(formParameters.getFirst(OAuth2ParameterNames.SCOPE))
			.isEqualTo(StringUtils.collectionToDelimitedString(clientRegistration.getScopes(), " "));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void convertWhenActorTokenIsJwtThenActorTokenTypeIsJwt() {
		// @formatter:off
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration()
				.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
				.scope("read", "write")
				.build();
		// @formatter:on
		this.actorToken = TestJwts.jwt().build();
		TokenExchangeGrantRequest grantRequest = new TokenExchangeGrantRequest(clientRegistration, this.subjectToken,
				this.actorToken);
		RequestEntity<?> requestEntity = this.converter.convert(grantRequest);
		assertThat(requestEntity).isNotNull();
		MultiValueMap<String, String> formParameters = (MultiValueMap<String, String>) requestEntity.getBody();
		assertThat(formParameters).isNotNull();
		assertThat(formParameters.getFirst(OAuth2ParameterNames.GRANT_TYPE))
			.isEqualTo(AuthorizationGrantType.TOKEN_EXCHANGE.getValue());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.REQUESTED_TOKEN_TYPE))
			.isEqualTo(ACCESS_TOKEN_TYPE_VALUE);
		assertThat(formParameters.getFirst(OAuth2ParameterNames.SUBJECT_TOKEN))
			.isEqualTo(this.subjectToken.getTokenValue());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE)).isEqualTo(ACCESS_TOKEN_TYPE_VALUE);
		assertThat(formParameters.getFirst(OAuth2ParameterNames.ACTOR_TOKEN))
			.isEqualTo(this.actorToken.getTokenValue());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.ACTOR_TOKEN_TYPE)).isEqualTo(JWT_TOKEN_TYPE_VALUE);
		assertThat(formParameters.getFirst(OAuth2ParameterNames.SCOPE))
			.isEqualTo(StringUtils.collectionToDelimitedString(clientRegistration.getScopes(), " "));
	}

}
