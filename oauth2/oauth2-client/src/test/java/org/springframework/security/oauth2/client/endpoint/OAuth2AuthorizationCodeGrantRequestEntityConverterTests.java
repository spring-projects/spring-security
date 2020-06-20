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
package org.springframework.security.oauth2.client.endpoint;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.ClientAssertionParameterNames;
import org.springframework.security.oauth2.core.endpoint.ClientAssertionParameterValues;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.util.MultiValueMap;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;

/**
 * Tests for {@link OAuth2AuthorizationCodeGrantRequestEntityConverter}.
 *
 * @author Joe Grandja
 */
public class OAuth2AuthorizationCodeGrantRequestEntityConverterTests {
	private OAuth2AuthorizationCodeGrantRequestEntityConverter converter = new OAuth2AuthorizationCodeGrantRequestEntityConverter();
	private ClientRegistration.Builder clientRegistrationBuilder = ClientRegistration
				.withRegistrationId("registration-1")
				.clientId("client-1")
				.clientSecret("secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUriTemplate("https://client.com/callback/client-1")
				.scope("read", "write")
				.authorizationUri("https://provider.com/oauth2/authorize")
				.tokenUri("https://provider.com/oauth2/token")
				.userInfoUri("https://provider.com/user")
				.userNameAttributeName("id")
				.clientName("client-1");

	private OAuth2AuthorizationRequest.Builder authorizationRequestBuilder = OAuth2AuthorizationRequest
				.authorizationCode()
				.clientId("client-1")
				.state("state-1234")
				.authorizationUri("https://provider.com/oauth2/authorize")
				.redirectUri("https://client.com/callback/client-1")
				.scopes(new HashSet(Arrays.asList("read", "write")));
	private OAuth2AuthorizationResponse.Builder authorizationResponseBuilder = OAuth2AuthorizationResponse
				.success("code-1234")
				.state("state-1234")
				.redirectUri("https://client.com/callback/client-1");


	@SuppressWarnings("unchecked")
	@Test
	public void convertWhenPkceGrantRequestValidThenConverts() {
		ClientRegistration clientRegistration = clientRegistrationBuilder
				.clientSecret(null)
				.build();

		Map<String, Object> attributes = new HashMap<>();
		attributes.put(PkceParameterNames.CODE_VERIFIER, "code-verifier-1234");

		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(PkceParameterNames.CODE_CHALLENGE, "code-challenge-1234");
		additionalParameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");

		OAuth2AuthorizationRequest authorizationRequest = authorizationRequestBuilder
				.attributes(attributes)
				.additionalParameters(additionalParameters)
				.build();

		OAuth2AuthorizationResponse authorizationResponse = authorizationResponseBuilder.build();
		OAuth2AuthorizationExchange authorizationExchange =
				new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse);
		OAuth2AuthorizationCodeGrantRequest authorizationCodeGrantRequest = new OAuth2AuthorizationCodeGrantRequest(
				clientRegistration, authorizationExchange);

		RequestEntity<?> requestEntity = this.converter.convert(authorizationCodeGrantRequest);

		assertThat(requestEntity.getMethod()).isEqualTo(HttpMethod.POST);
		assertThat(requestEntity.getUrl().toASCIIString()).isEqualTo(
				clientRegistration.getProviderDetails().getTokenUri());

		HttpHeaders headers = requestEntity.getHeaders();
		assertThat(headers.getAccept()).contains(MediaType.APPLICATION_JSON_UTF8);
		assertThat(headers.getContentType()).isEqualTo(
				MediaType.valueOf(APPLICATION_FORM_URLENCODED_VALUE + ";charset=UTF-8"));
		assertThat(headers.getFirst(HttpHeaders.AUTHORIZATION)).isNull();

		MultiValueMap<String, String> formParameters = (MultiValueMap<String, String>) requestEntity.getBody();
		assertThat(formParameters.getFirst(OAuth2ParameterNames.GRANT_TYPE)).isEqualTo(
				AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.CODE)).isEqualTo("code-1234");
		assertThat(formParameters.getFirst(OAuth2ParameterNames.REDIRECT_URI)).isEqualTo(
				clientRegistration.getRedirectUriTemplate());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.CLIENT_ID)).isEqualTo("client-1");
		assertThat(formParameters.getFirst(PkceParameterNames.CODE_VERIFIER)).isEqualTo("code-verifier-1234");
	}

	@SuppressWarnings("unchecked")
	@Test
	public void convertWhenGrantRequestValidWithAssertionThenConverts() {
		ClientRegistration clientRegistration = clientRegistrationBuilder.build();
		OAuth2AuthorizationRequest authorizationRequest = authorizationRequestBuilder.build();
		OAuth2AuthorizationResponse authorizationResponse = authorizationResponseBuilder.build();
		OAuth2AuthorizationExchange authorizationExchange =
				new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse);
		OAuth2AuthorizationCodeGrantRequest authorizationCodeGrantRequest = new OAuth2AuthorizationCodeGrantRequest(
				clientRegistration, authorizationExchange);

		RequestEntity<?> requestEntity = this.converter.convert(authorizationCodeGrantRequest);

		assertThat(requestEntity.getMethod()).isEqualTo(HttpMethod.POST);
		assertThat(requestEntity.getUrl().toASCIIString()).isEqualTo(
				clientRegistration.getProviderDetails().getTokenUri());

		HttpHeaders headers = requestEntity.getHeaders();
		assertThat(headers.getAccept()).contains(MediaType.APPLICATION_JSON_UTF8);
		assertThat(headers.getContentType()).isEqualTo(
				MediaType.valueOf(APPLICATION_FORM_URLENCODED_VALUE + ";charset=UTF-8"));
		assertThat(headers.getFirst(HttpHeaders.AUTHORIZATION)).startsWith("Basic ");

		MultiValueMap<String, String> formParameters = (MultiValueMap<String, String>) requestEntity.getBody();
		assertThat(formParameters.getFirst(OAuth2ParameterNames.GRANT_TYPE)).isEqualTo(
				AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.CODE)).isEqualTo("code-1234");
		assertThat(formParameters.getFirst(OAuth2ParameterNames.CLIENT_ID)).isNull();
		assertThat(formParameters.getFirst(OAuth2ParameterNames.REDIRECT_URI)).isEqualTo(
				clientRegistration.getRedirectUriTemplate());
	}


	@SuppressWarnings("unchecked")
	@Test
	public void convertWhenGrantRequestValidThenConverts() {

		ClientRegistration clientRegistration = this.from(clientRegistrationBuilder.build())
				.clientAuthenticationMethod(ClientAuthenticationMethod.SECRET_JWT)
				.clientSecret("2ae2135579004d5d87ae8241603c0a5c")
				.clientId("client-1").build();

		OAuth2AuthorizationRequest authorizationRequest = authorizationRequestBuilder.build();
		OAuth2AuthorizationResponse authorizationResponse = authorizationResponseBuilder.build();
		OAuth2AuthorizationExchange authorizationExchange =
				new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse);
		OAuth2AuthorizationCodeGrantRequest authorizationCodeGrantRequest = new OAuth2AuthorizationCodeGrantRequest(
				clientRegistration, authorizationExchange);

		RequestEntity<?> requestEntity = this.converter.convert(authorizationCodeGrantRequest);

		assertThat(requestEntity.getMethod()).isEqualTo(HttpMethod.POST);
		assertThat(requestEntity.getUrl().toASCIIString()).isEqualTo(
				clientRegistration.getProviderDetails().getTokenUri());

		HttpHeaders headers = requestEntity.getHeaders();
		assertThat(headers.getAccept()).contains(MediaType.APPLICATION_JSON_UTF8);
		assertThat(headers.getContentType()).isEqualTo(
				MediaType.valueOf(APPLICATION_FORM_URLENCODED_VALUE + ";charset=UTF-8"));

		MultiValueMap<String, String> formParameters = (MultiValueMap<String, String>) requestEntity.getBody();
		assertThat(formParameters.getFirst(OAuth2ParameterNames.GRANT_TYPE)).isEqualTo(
				AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.CODE)).isEqualTo("code-1234");
		assertThat(formParameters.getFirst(OAuth2ParameterNames.CLIENT_ID)).isEqualTo("client-1");
		assertThat(formParameters.getFirst(OAuth2ParameterNames.REDIRECT_URI)).isEqualTo(
				clientRegistration.getRedirectUriTemplate());
		assertThat(formParameters.getFirst(ClientAssertionParameterNames.CLIENT_ASSERTION_TYPE))
				.isEqualTo(ClientAssertionParameterValues.CLIENT_ASSERTION_TYPE_JWT_BEARER);
		assertThat(formParameters.getFirst(ClientAssertionParameterNames.CLIENT_ASSERTION))
				.isNotEmpty();
		assertTrue(validateJWTSecret(formParameters.getFirst(ClientAssertionParameterNames.CLIENT_ASSERTION),clientRegistration));

	}

	@SuppressWarnings("unchecked")
	@Test(expected = OAuth2AuthenticationException.class)
	public void convertWhenGrantRequestInValidTokenThenConvertFails() {

		ClientRegistration clientRegistration = this.from(clientRegistrationBuilder.build())
				.clientAuthenticationMethod(ClientAuthenticationMethod.SECRET_JWT)
				.clientSecret("2ae2135579004d5d87ae8241603c0a5c")
				.tokenUri("/http$$$##://token.com").build();

		OAuth2AuthorizationRequest authorizationRequest = authorizationRequestBuilder.build();
		OAuth2AuthorizationResponse authorizationResponse = authorizationResponseBuilder.build();
		OAuth2AuthorizationExchange authorizationExchange =
				new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse);
		OAuth2AuthorizationCodeGrantRequest authorizationCodeGrantRequest = new OAuth2AuthorizationCodeGrantRequest(
				clientRegistration, authorizationExchange);

		RequestEntity<?> requestEntity = this.converter.convert(authorizationCodeGrantRequest);
	}

	@SuppressWarnings("unchecked")
	@Test(expected = OAuth2AuthenticationException.class)
	public void convertWhenGrantRequestInValidSecretLengthThenConvertFails() {

		ClientRegistration clientRegistration = this.from(clientRegistrationBuilder.build())
				.clientAuthenticationMethod(ClientAuthenticationMethod.SECRET_JWT)
				.clientSecret("2ae2135579004d5d87ae8241600a5c").build();

		OAuth2AuthorizationRequest authorizationRequest = authorizationRequestBuilder.build();
		OAuth2AuthorizationResponse authorizationResponse = authorizationResponseBuilder.build();
		OAuth2AuthorizationExchange authorizationExchange =
				new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse);
		OAuth2AuthorizationCodeGrantRequest authorizationCodeGrantRequest = new OAuth2AuthorizationCodeGrantRequest(
				clientRegistration, authorizationExchange);

		RequestEntity<?> requestEntity = this.converter.convert(authorizationCodeGrantRequest);
	}

	private boolean validateJWTSecret(String jwt,ClientRegistration registration ){

		boolean success;

		try{
			SignedJWT signedJWT = SignedJWT.parse(jwt);
			JWSVerifier jwsVerifier = new MACVerifier(registration.getClientSecret());
			signedJWT.verify(jwsVerifier);
			assertThat(signedJWT.getJWTClaimsSet().getAudience().equals(registration.getProviderDetails().getTokenUri()));
			assertThat(signedJWT.getJWTClaimsSet().getSubject().equals(registration.getClientId()));
			assertThat(new Date().before(signedJWT.getJWTClaimsSet().getExpirationTime()));
			success = true;

		}catch(Exception e){
			success = false;
		}

		return success;

	}


	private ClientRegistration.Builder from(ClientRegistration registration) {
		return ClientRegistration.withRegistrationId(registration.getRegistrationId())
				.clientId(registration.getClientId())
				.clientSecret(registration.getClientSecret())
				.clientAuthenticationMethod(registration.getClientAuthenticationMethod())
				.authorizationGrantType(registration.getAuthorizationGrantType())
				.redirectUriTemplate(registration.getRedirectUriTemplate())
				.scope(registration.getScopes())
				.authorizationUri(registration.getProviderDetails().getAuthorizationUri())
				.tokenUri(registration.getProviderDetails().getTokenUri())
				.userInfoUri(registration.getProviderDetails().getUserInfoEndpoint().getUri())
				.userNameAttributeName(registration.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName())
				.clientName(registration.getClientName());
	}
}
