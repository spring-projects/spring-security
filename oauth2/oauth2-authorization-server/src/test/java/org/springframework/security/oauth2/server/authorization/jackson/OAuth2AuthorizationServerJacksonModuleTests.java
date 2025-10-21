/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.oauth2.server.authorization.jackson;

import java.security.Principal;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeActor;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeCompositeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link OAuth2AuthorizationServerJackson2Module}.
 *
 * @author Steve Riesenberg
 * @author Joe Grandja
 */
@SuppressWarnings("removal")
public class OAuth2AuthorizationServerJacksonModuleTests {

	private static final TypeReference<Map<String, Object>> STRING_OBJECT_MAP = new TypeReference<>() {
	};

	private JsonMapper mapper;

	@BeforeEach
	public void setup() {
		this.mapper = JsonMapper.builder().addModules(new OAuth2AuthorizationServerJacksonModule()).build();
	}

	@Test
	public void readValueWhenOAuth2AuthorizationAttributesThenSuccess() {
		Authentication principal = new UsernamePasswordAuthenticationToken("principal", "credentials");
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization()
			.attributes((attrs) -> attrs.put(Principal.class.getName(), principal))
			.build();
		Map<String, Object> attributes = authorization.getAttributes();
		String json = this.mapper.writeValueAsString(attributes);
		assertThat(this.mapper.readValue(json, STRING_OBJECT_MAP)).isEqualTo(attributes);
	}

	@Test
	public void readValueWhenOAuth2AccessTokenMetadataThenSuccess() {
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization().build();
		Map<String, Object> metadata = authorization.getAccessToken().getMetadata();
		String json = this.mapper.writeValueAsString(metadata);
		assertThat(this.mapper.readValue(json, STRING_OBJECT_MAP)).isEqualTo(metadata);
	}

	@Test
	public void readValueWhenClientSettingsThenSuccess() {
		ClientSettings clientSettings = ClientSettings.builder()
			.tokenEndpointAuthenticationSigningAlgorithm(MacAlgorithm.HS256)
			.build();
		Map<String, Object> clientSettingsMap = clientSettings.getSettings();
		String json = this.mapper.writeValueAsString(clientSettingsMap);
		assertThat(this.mapper.readValue(json, STRING_OBJECT_MAP)).isEqualTo(clientSettingsMap);
	}

	@Test
	public void readValueWhenTokenSettingsThenSuccess() {
		TokenSettings tokenSettings = TokenSettings.builder().build();
		Map<String, Object> tokenSettingsMap = tokenSettings.getSettings();
		String json = this.mapper.writeValueAsString(tokenSettingsMap);
		assertThat(this.mapper.readValue(json, STRING_OBJECT_MAP)).isEqualTo(tokenSettingsMap);
	}

	@Test
	public void readValueWhenOAuth2TokenExchangeCompositeAuthenticationTokenThenSuccess() {
		Authentication subject = new UsernamePasswordAuthenticationToken("principal", "credentials");
		OAuth2TokenExchangeActor actor1 = new OAuth2TokenExchangeActor(
				Map.of(JwtClaimNames.ISS, "issuer-1", JwtClaimNames.SUB, "actor1"));
		OAuth2TokenExchangeActor actor2 = new OAuth2TokenExchangeActor(
				Map.of(JwtClaimNames.ISS, "issuer-2", JwtClaimNames.SUB, "actor2"));
		OAuth2TokenExchangeCompositeAuthenticationToken authentication = new OAuth2TokenExchangeCompositeAuthenticationToken(
				subject, List.of(actor1, actor2));
		String json = this.mapper.writeValueAsString(authentication);
		assertThat(this.mapper.readValue(json, OAuth2TokenExchangeCompositeAuthenticationToken.class))
			.isEqualTo(authentication);
	}

}
