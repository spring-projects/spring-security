/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.oauth2.client.jackson2;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Before;
import org.junit.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationRequests;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link OAuth2AuthorizationRequestMixin}.
 *
 * @author Joe Grandja
 */
public class OAuth2AuthorizationRequestMixinTests {

	private ObjectMapper mapper;

	private OAuth2AuthorizationRequest.Builder authorizationRequestBuilder;

	@Before
	public void setup() {
		ClassLoader loader = getClass().getClassLoader();
		this.mapper = new ObjectMapper();
		this.mapper.registerModules(SecurityJackson2Modules.getModules(loader));
		Map<String, Object> additionalParameters = new LinkedHashMap<>();
		additionalParameters.put("param1", "value1");
		additionalParameters.put("param2", "value2");
		this.authorizationRequestBuilder = TestOAuth2AuthorizationRequests.request().scope("read", "write")
				.additionalParameters(additionalParameters);
	}

	@Test
	public void serializeWhenMixinRegisteredThenSerializes() throws Exception {
		OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestBuilder.build();
		String expectedJson = asJson(authorizationRequest);
		String json = this.mapper.writeValueAsString(authorizationRequest);
		JSONAssert.assertEquals(expectedJson, json, true);
	}

	@Test
	public void serializeWhenRequiredAttributesOnlyThenSerializes() throws Exception {
		OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestBuilder.scopes(null).state(null)
				.additionalParameters(Map::clear).attributes(Map::clear).build();
		String expectedJson = asJson(authorizationRequest);
		String json = this.mapper.writeValueAsString(authorizationRequest);
		JSONAssert.assertEquals(expectedJson, json, true);
	}

	@Test
	public void deserializeWhenMixinNotRegisteredThenThrowJsonProcessingException() {
		String json = asJson(this.authorizationRequestBuilder.build());
		assertThatThrownBy(() -> new ObjectMapper().readValue(json, OAuth2AuthorizationRequest.class))
				.isInstanceOf(JsonProcessingException.class);
	}

	@Test
	public void deserializeWhenMixinRegisteredThenDeserializes() throws Exception {
		OAuth2AuthorizationRequest expectedAuthorizationRequest = this.authorizationRequestBuilder.build();
		String json = asJson(expectedAuthorizationRequest);
		OAuth2AuthorizationRequest authorizationRequest = this.mapper.readValue(json, OAuth2AuthorizationRequest.class);
		assertThat(authorizationRequest.getAuthorizationUri())
				.isEqualTo(expectedAuthorizationRequest.getAuthorizationUri());
		assertThat(authorizationRequest.getGrantType()).isEqualTo(expectedAuthorizationRequest.getGrantType());
		assertThat(authorizationRequest.getResponseType()).isEqualTo(expectedAuthorizationRequest.getResponseType());
		assertThat(authorizationRequest.getClientId()).isEqualTo(expectedAuthorizationRequest.getClientId());
		assertThat(authorizationRequest.getRedirectUri()).isEqualTo(expectedAuthorizationRequest.getRedirectUri());
		assertThat(authorizationRequest.getScopes()).isEqualTo(expectedAuthorizationRequest.getScopes());
		assertThat(authorizationRequest.getState()).isEqualTo(expectedAuthorizationRequest.getState());
		assertThat(authorizationRequest.getAdditionalParameters())
				.containsExactlyEntriesOf(expectedAuthorizationRequest.getAdditionalParameters());
		assertThat(authorizationRequest.getAuthorizationRequestUri())
				.isEqualTo(expectedAuthorizationRequest.getAuthorizationRequestUri());
		assertThat(authorizationRequest.getAttributes())
				.containsExactlyEntriesOf(expectedAuthorizationRequest.getAttributes());
	}

	@Test
	public void deserializeWhenRequiredAttributesOnlyThenDeserializes() throws Exception {
		OAuth2AuthorizationRequest expectedAuthorizationRequest = this.authorizationRequestBuilder.scopes(null)
				.state(null).additionalParameters(Map::clear).attributes(Map::clear).build();
		String json = asJson(expectedAuthorizationRequest);
		OAuth2AuthorizationRequest authorizationRequest = this.mapper.readValue(json, OAuth2AuthorizationRequest.class);
		assertThat(authorizationRequest.getAuthorizationUri())
				.isEqualTo(expectedAuthorizationRequest.getAuthorizationUri());
		assertThat(authorizationRequest.getGrantType()).isEqualTo(expectedAuthorizationRequest.getGrantType());
		assertThat(authorizationRequest.getResponseType()).isEqualTo(expectedAuthorizationRequest.getResponseType());
		assertThat(authorizationRequest.getClientId()).isEqualTo(expectedAuthorizationRequest.getClientId());
		assertThat(authorizationRequest.getRedirectUri()).isEqualTo(expectedAuthorizationRequest.getRedirectUri());
		assertThat(authorizationRequest.getScopes()).isEmpty();
		assertThat(authorizationRequest.getState()).isNull();
		assertThat(authorizationRequest.getAdditionalParameters()).isEmpty();
		assertThat(authorizationRequest.getAuthorizationRequestUri())
				.isEqualTo(expectedAuthorizationRequest.getAuthorizationRequestUri());
		assertThat(authorizationRequest.getAttributes()).isEmpty();
	}

	@Test
	public void deserializeWhenInvalidAuthorizationGrantTypeThenThrowJsonParseException() {
		OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestBuilder.build();
		String json = asJson(authorizationRequest).replace("authorization_code", "client_credentials");
		assertThatThrownBy(() -> this.mapper.readValue(json, OAuth2AuthorizationRequest.class))
				.isInstanceOf(JsonParseException.class).hasMessageContaining("Invalid authorizationGrantType");
	}

	private static String asJson(OAuth2AuthorizationRequest authorizationRequest) {
		String scopes = "";
		if (!CollectionUtils.isEmpty(authorizationRequest.getScopes())) {
			scopes = StringUtils.collectionToDelimitedString(authorizationRequest.getScopes(), ",", "\"", "\"");
		}
		String additionalParameters = "\"@class\": \"java.util.Collections$UnmodifiableMap\"";
		if (!CollectionUtils.isEmpty(authorizationRequest.getAdditionalParameters())) {
			additionalParameters += "," + authorizationRequest.getAdditionalParameters().keySet().stream().map(
					(key) -> "\"" + key + "\": \"" + authorizationRequest.getAdditionalParameters().get(key) + "\"")
					.collect(Collectors.joining(","));
		}
		String attributes = "\"@class\": \"java.util.Collections$UnmodifiableMap\"";
		if (!CollectionUtils.isEmpty(authorizationRequest.getAttributes())) {
			attributes += "," + authorizationRequest.getAttributes().keySet().stream()
					.map((key) -> "\"" + key + "\": \"" + authorizationRequest.getAttributes().get(key) + "\"")
					.collect(Collectors.joining(","));
		}
		// @formatter:off
		return "{\n" +
				"  \"@class\": \"org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest\",\n" +
				"  \"authorizationUri\": \"" + authorizationRequest.getAuthorizationUri() + "\",\n" +
				"  \"authorizationGrantType\": {\n" +
				"    \"value\": \"" + authorizationRequest.getGrantType().getValue() + "\"\n" +
				"  },\n" +
				"  \"responseType\": {\n" +
				"    \"value\": \"" + authorizationRequest.getResponseType().getValue() + "\"\n" +
				"  },\n" +
				"  \"clientId\": \"" + authorizationRequest.getClientId() + "\",\n" +
				"  \"redirectUri\": \"" + authorizationRequest.getRedirectUri() + "\",\n" +
				"  \"scopes\": [\n" +
				"    \"java.util.Collections$UnmodifiableSet\",\n" +
				"    [" + scopes + "]\n" +
				"  ],\n" +
				"  \"state\": " + (authorizationRequest.getState() != null ? "\"" + authorizationRequest.getState() + "\"" : "null") + ",\n" +
				"  \"additionalParameters\": {\n" +
				"    " + additionalParameters + "\n" +
				"  },\n" +
				"  \"authorizationRequestUri\": \"" + authorizationRequest.getAuthorizationRequestUri() + "\",\n" +
				"  \"attributes\": {\n" +
				"    " + attributes + "\n" +
				"  }\n" +
				"}";
		// @formatter:on
	}

}
