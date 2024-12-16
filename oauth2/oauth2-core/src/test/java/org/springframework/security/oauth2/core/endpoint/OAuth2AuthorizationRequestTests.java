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

package org.springframework.security.oauth2.core.endpoint;

import java.net.URI;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.core.AuthorizationGrantType;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link OAuth2AuthorizationRequest}.
 *
 * @author Luander Ribeiro
 * @author Joe Grandja
 */
public class OAuth2AuthorizationRequestTests {

	private static final String AUTHORIZATION_URI = "https://provider.com/oauth2/authorize";

	private static final String CLIENT_ID = "client-id";

	private static final String REDIRECT_URI = "https://example.com";

	private static final Set<String> SCOPES = new LinkedHashSet<>(Arrays.asList("scope1", "scope2"));

	private static final String STATE = "state";

	@Test
	public void buildWhenAuthorizationUriIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> OAuth2AuthorizationRequest
						.authorizationCode()
						.authorizationUri(null)
						.clientId(CLIENT_ID)
						.redirectUri(REDIRECT_URI)
						.scopes(SCOPES)
						.state(STATE)
						.build()
				);
		// @formatter:on
	}

	@Test
	public void buildWhenClientIdIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> OAuth2AuthorizationRequest.authorizationCode()
						.authorizationUri(AUTHORIZATION_URI)
						.clientId(null)
						.redirectUri(REDIRECT_URI)
						.scopes(SCOPES)
						.state(STATE)
						.build()
				);
		// @formatter:on
	}

	@Test
	public void buildWhenRedirectUriIsNullForAuthorizationCodeThenDoesNotThrowAnyException() {
		// @formatter:off
		OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri(AUTHORIZATION_URI)
				.clientId(CLIENT_ID)
				.redirectUri(null)
				.scopes(SCOPES)
				.state(STATE)
				.build();
		// @formatter:on
	}

	@Test
	public void buildWhenScopesIsNullThenDoesNotThrowAnyException() {
		// @formatter:off
		OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri(AUTHORIZATION_URI)
				.clientId(CLIENT_ID)
				.redirectUri(REDIRECT_URI)
				.scopes(null)
				.state(STATE)
				.build();
		// @formatter:on
	}

	@Test
	public void buildWhenStateIsNullThenDoesNotThrowAnyException() {
		// @formatter:off
		OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri(AUTHORIZATION_URI)
				.clientId(CLIENT_ID)
				.redirectUri(REDIRECT_URI)
				.scopes(SCOPES)
				.state(null)
				.build();
		// @formatter:on
	}

	@Test
	public void buildWhenAdditionalParametersEmptyThenDoesNotThrowAnyException() {
		// @formatter:off
		OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri(AUTHORIZATION_URI)
				.clientId(CLIENT_ID)
				.redirectUri(REDIRECT_URI)
				.scopes(SCOPES)
				.state(STATE)
				.additionalParameters(Map::clear)
				.build();
		// @formatter:on
	}

	@Test
	public void buildWhenAuthorizationCodeThenGrantTypeResponseTypeIsSet() {
		// @formatter:off
		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri(AUTHORIZATION_URI)
				.clientId(CLIENT_ID)
				.redirectUri(null)
				.scopes(SCOPES)
				.state(STATE)
				.build();
		// @formatter:on
		assertThat(authorizationRequest.getGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(authorizationRequest.getResponseType()).isEqualTo(OAuth2AuthorizationResponseType.CODE);
	}

	@Test
	public void buildWhenAllValuesProvidedThenAllValuesAreSet() {
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put("param1", "value1");
		additionalParameters.put("param2", "value2");
		Map<String, Object> attributes = new HashMap<>();
		attributes.put("attribute1", "value1");
		attributes.put("attribute2", "value2");
		// @formatter:off
		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri(AUTHORIZATION_URI)
				.clientId(CLIENT_ID)
				.redirectUri(REDIRECT_URI)
				.scopes(SCOPES)
				.state(STATE)
				.additionalParameters(additionalParameters)
				.attributes(attributes)
				.authorizationRequestUri(AUTHORIZATION_URI)
				.build();
		// @formatter:on
		assertThat(authorizationRequest.getAuthorizationUri()).isEqualTo(AUTHORIZATION_URI);
		assertThat(authorizationRequest.getGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(authorizationRequest.getResponseType()).isEqualTo(OAuth2AuthorizationResponseType.CODE);
		assertThat(authorizationRequest.getClientId()).isEqualTo(CLIENT_ID);
		assertThat(authorizationRequest.getRedirectUri()).isEqualTo(REDIRECT_URI);
		assertThat(authorizationRequest.getScopes()).isEqualTo(SCOPES);
		assertThat(authorizationRequest.getState()).isEqualTo(STATE);
		assertThat(authorizationRequest.getAdditionalParameters()).isEqualTo(additionalParameters);
		assertThat(authorizationRequest.getAttributes()).isEqualTo(attributes);
		assertThat(authorizationRequest.getAuthorizationRequestUri()).isEqualTo(AUTHORIZATION_URI);
	}

	@Test
	public void buildWhenAuthorizationRequestUriSetThenOverridesDefault() {
		// @formatter:off
		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri(AUTHORIZATION_URI)
				.clientId(CLIENT_ID)
				.redirectUri(REDIRECT_URI)
				.scopes(SCOPES)
				.state(STATE)
				.authorizationRequestUri(AUTHORIZATION_URI)
				.build();
		// @formatter:on
		assertThat(authorizationRequest.getAuthorizationRequestUri()).isEqualTo(AUTHORIZATION_URI);
	}

	@Test
	public void buildWhenAuthorizationRequestUriFunctionSetThenOverridesDefault() {
		// @formatter:off
		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri(AUTHORIZATION_URI)
				.clientId(CLIENT_ID)
				.redirectUri(REDIRECT_URI)
				.scopes(SCOPES)
				.state(STATE)
				.authorizationRequestUri((uriBuilder) -> URI.create(AUTHORIZATION_URI))
				.build();
		// @formatter:on
		assertThat(authorizationRequest.getAuthorizationRequestUri()).isEqualTo(AUTHORIZATION_URI);
	}

	@Test
	public void buildWhenAuthorizationRequestUriNotSetThenDefaultSet() {
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put("param1", "value1");
		additionalParameters.put("param2", "value2");
		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
			.authorizationUri(AUTHORIZATION_URI)
			.clientId(CLIENT_ID)
			.redirectUri(REDIRECT_URI)
			.scopes(SCOPES)
			.state(STATE)
			.additionalParameters(additionalParameters)
			.build();
		assertThat(authorizationRequest.getAuthorizationRequestUri()).isNotNull();
		assertThat(authorizationRequest.getAuthorizationRequestUri()).isEqualTo("https://provider.com/oauth2/authorize?"
				+ "response_type=code&client_id=client-id&" + "scope=scope1%20scope2&state=state&"
				+ "redirect_uri=https://example.com&param1=value1&param2=value2");
	}

	@Test
	public void buildWhenRequiredParametersSetThenAuthorizationRequestUriIncludesRequiredParametersOnly() {
		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
			.authorizationUri(AUTHORIZATION_URI)
			.clientId(CLIENT_ID)
			.build();
		assertThat(authorizationRequest.getAuthorizationRequestUri())
			.isEqualTo("https://provider.com/oauth2/authorize?response_type=code&client_id=client-id");
	}

	@Test
	public void fromWhenAuthorizationRequestIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> OAuth2AuthorizationRequest.from(null));
	}

	@Test
	public void fromWhenAuthorizationRequestProvidedThenValuesAreCopied() {
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put("param1", "value1");
		additionalParameters.put("param2", "value2");
		Map<String, Object> attributes = new HashMap<>();
		attributes.put("attribute1", "value1");
		attributes.put("attribute2", "value2");
		// @formatter:off
		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri(AUTHORIZATION_URI)
				.clientId(CLIENT_ID)
				.redirectUri(REDIRECT_URI)
				.scopes(SCOPES)
				.state(STATE)
				.additionalParameters(additionalParameters)
				.attributes(attributes)
				.build();
		OAuth2AuthorizationRequest authorizationRequestCopy = OAuth2AuthorizationRequest.from(authorizationRequest)
				.build();
		// @formatter:on
		assertThat(authorizationRequestCopy.getAuthorizationUri())
			.isEqualTo(authorizationRequest.getAuthorizationUri());
		assertThat(authorizationRequestCopy.getGrantType()).isEqualTo(authorizationRequest.getGrantType());
		assertThat(authorizationRequestCopy.getResponseType()).isEqualTo(authorizationRequest.getResponseType());
		assertThat(authorizationRequestCopy.getClientId()).isEqualTo(authorizationRequest.getClientId());
		assertThat(authorizationRequestCopy.getRedirectUri()).isEqualTo(authorizationRequest.getRedirectUri());
		assertThat(authorizationRequestCopy.getScopes()).isEqualTo(authorizationRequest.getScopes());
		assertThat(authorizationRequestCopy.getState()).isEqualTo(authorizationRequest.getState());
		assertThat(authorizationRequestCopy.getAdditionalParameters())
			.isEqualTo(authorizationRequest.getAdditionalParameters());
		assertThat(authorizationRequestCopy.getAttributes()).isEqualTo(authorizationRequest.getAttributes());
		assertThat(authorizationRequestCopy.getAuthorizationRequestUri())
			.isEqualTo(authorizationRequest.getAuthorizationRequestUri());
	}

	@Test
	public void buildWhenAuthorizationUriIncludesQueryParameterThenAuthorizationRequestUrlIncludesIt() {
		OAuth2AuthorizationRequest authorizationRequest = TestOAuth2AuthorizationRequests.request()
			.authorizationUri(AUTHORIZATION_URI + "?param1=value1&param2=value2")
			.build();
		assertThat(authorizationRequest.getAuthorizationRequestUri()).isNotNull();
		assertThat(authorizationRequest.getAuthorizationRequestUri()).isEqualTo("https://provider.com/oauth2/authorize?"
				+ "param1=value1&param2=value2&" + "response_type=code&client_id=client-id&state=state&"
				+ "redirect_uri=https://example.com/authorize/oauth2/code/registration-id");
	}

	@Test
	public void buildWhenAuthorizationUriIncludesEscapedQueryParameterThenAuthorizationRequestUrlIncludesIt() {
		OAuth2AuthorizationRequest authorizationRequest = TestOAuth2AuthorizationRequests.request()
			.authorizationUri(AUTHORIZATION_URI
					+ "?claims=%7B%22userinfo%22%3A%7B%22email_verified%22%3A%7B%22essential%22%3Atrue%7D%7D%7D")
			.build();
		assertThat(authorizationRequest.getAuthorizationRequestUri()).isNotNull();
		assertThat(authorizationRequest.getAuthorizationRequestUri()).isEqualTo("https://provider.com/oauth2/authorize?"
				+ "claims=%7B%22userinfo%22%3A%7B%22email_verified%22%3A%7B%22essential%22%3Atrue%7D%7D%7D&"
				+ "response_type=code&client_id=client-id&state=state&"
				+ "redirect_uri=https://example.com/authorize/oauth2/code/registration-id");
	}

	@Test
	public void buildWhenNonAsciiAdditionalParametersThenProperlyEncoded() {
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put("item amount", "19.95" + '\u20ac');
		additionalParameters.put("item name", "H" + '\u00c5' + "M" + '\u00d6');
		additionalParameters.put('\u00e2' + "ge", "4" + '\u00bd');
		OAuth2AuthorizationRequest authorizationRequest = TestOAuth2AuthorizationRequests.request()
			.additionalParameters(additionalParameters)
			.build();
		assertThat(authorizationRequest.getAuthorizationRequestUri()).isNotNull();
		assertThat(authorizationRequest.getAuthorizationRequestUri()).isEqualTo(
				"https://example.com/login/oauth/authorize?" + "response_type=code&client_id=client-id&state=state&"
						+ "redirect_uri=https://example.com/authorize/oauth2/code/registration-id&"
						+ "item%20amount=19.95%E2%82%AC&%C3%A2ge=4%C2%BD&item%20name=H%C3%85M%C3%96");
	}

	@Test
	public void buildWhenAdditionalParametersContainsArrayThenProperlyEncoded() {
		Map<String, Object> additionalParameters = new LinkedHashMap<>();
		additionalParameters.put("item1", new String[] { "1", "2" });
		additionalParameters.put("item2", "value2");
		OAuth2AuthorizationRequest authorizationRequest = TestOAuth2AuthorizationRequests.request()
			.additionalParameters(additionalParameters)
			.build();
		assertThat(authorizationRequest.getAuthorizationRequestUri()).isNotNull();
		assertThat(authorizationRequest.getAuthorizationRequestUri())
			.isEqualTo("https://example.com/login/oauth/authorize?response_type=code&client_id=client-id&state=state&"
					+ "redirect_uri=https://example.com/authorize/oauth2/code/registration-id&"
					+ "item1=1&item1=2&item2=value2");
	}

	@Test
	public void buildWhenAdditionalParametersContainsIterableThenProperlyEncoded() {
		Map<String, Object> additionalParameters = new LinkedHashMap<>();
		additionalParameters.put("item1", Arrays.asList("1", "2"));
		additionalParameters.put("item2", "value2");
		OAuth2AuthorizationRequest authorizationRequest = TestOAuth2AuthorizationRequests.request()
			.additionalParameters(additionalParameters)
			.build();
		assertThat(authorizationRequest.getAuthorizationRequestUri()).isNotNull();
		assertThat(authorizationRequest.getAuthorizationRequestUri())
			.isEqualTo("https://example.com/login/oauth/authorize?response_type=code&client_id=client-id&state=state&"
					+ "redirect_uri=https://example.com/authorize/oauth2/code/registration-id&"
					+ "item1=1&item1=2&item2=value2");
	}

	@Test
	public void buildWhenAdditionalParametersContainsNullThenAuthorizationRequestUriContainsNull() {
		Map<String, Object> additionalParameters = new LinkedHashMap<>();
		additionalParameters.put("item1", null);
		additionalParameters.put("item2", "value2");
		OAuth2AuthorizationRequest authorizationRequest = TestOAuth2AuthorizationRequests.request()
			.additionalParameters(additionalParameters)
			.build();
		assertThat(authorizationRequest.getAuthorizationRequestUri()).isNotNull();
		assertThat(authorizationRequest.getAuthorizationRequestUri())
			.isEqualTo("https://example.com/login/oauth/authorize?response_type=code&client_id=client-id&state=state&"
					+ "redirect_uri=https://example.com/authorize/oauth2/code/registration-id&"
					+ "item1=null&item2=value2");
	}

}
