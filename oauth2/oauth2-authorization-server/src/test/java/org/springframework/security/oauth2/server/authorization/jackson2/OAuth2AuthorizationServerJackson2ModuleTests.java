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

package org.springframework.security.oauth2.server.authorization.jackson2;

import java.security.Principal;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeActor;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeCompositeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link OAuth2AuthorizationServerJackson2Module}.
 *
 * @author Steve Riesenberg
 * @author Joe Grandja
 */
public class OAuth2AuthorizationServerJackson2ModuleTests {

	private static final TypeReference<Map<String, Object>> STRING_OBJECT_MAP = new TypeReference<>() {
	};

	private ObjectMapper objectMapper;

	@BeforeEach
	public void setup() {
		this.objectMapper = new ObjectMapper();
		ClassLoader classLoader = OAuth2AuthorizationServerJackson2Module.class.getClassLoader();
		List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
		this.objectMapper.registerModules(securityModules);
		this.objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
	}

	@Test
	public void readValueWhenOAuth2AuthorizationAttributesThenSuccess() throws Exception {
		Authentication principal = new UsernamePasswordAuthenticationToken("principal", "credentials");
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization()
			.attributes(attrs -> attrs.put(Principal.class.getName(), principal))
			.build();
		Map<String, Object> attributes = authorization.getAttributes();
		String json = this.objectMapper.writeValueAsString(attributes);
		assertThat(this.objectMapper.readValue(json, STRING_OBJECT_MAP)).isEqualTo(attributes);
	}

	@Test
	public void readValueWhenOAuth2AccessTokenMetadataThenSuccess() throws Exception {
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization().build();
		Map<String, Object> metadata = authorization.getAccessToken().getMetadata();
		String json = this.objectMapper.writeValueAsString(metadata);
		assertThat(this.objectMapper.readValue(json, STRING_OBJECT_MAP)).isEqualTo(metadata);
	}

	@Test
	public void readValueWhenClientSettingsThenSuccess() throws Exception {
		ClientSettings clientSettings = ClientSettings.builder()
			.tokenEndpointAuthenticationSigningAlgorithm(MacAlgorithm.HS256)
			.build();
		Map<String, Object> clientSettingsMap = clientSettings.getSettings();
		String json = this.objectMapper.writeValueAsString(clientSettingsMap);
		assertThat(this.objectMapper.readValue(json, STRING_OBJECT_MAP)).isEqualTo(clientSettingsMap);
	}

	@Test
	public void readValueWhenTokenSettingsThenSuccess() throws Exception {
		TokenSettings tokenSettings = TokenSettings.builder().build();
		Map<String, Object> tokenSettingsMap = tokenSettings.getSettings();
		String json = this.objectMapper.writeValueAsString(tokenSettingsMap);
		assertThat(this.objectMapper.readValue(json, STRING_OBJECT_MAP)).isEqualTo(tokenSettingsMap);
	}

	@Test
	public void readValueWhenOAuth2TokenExchangeCompositeAuthenticationTokenThenSuccess() throws Exception {
		Authentication subject = new UsernamePasswordAuthenticationToken("principal", "credentials");
		OAuth2TokenExchangeActor actor1 = new OAuth2TokenExchangeActor(
				Map.of(JwtClaimNames.ISS, "issuer-1", JwtClaimNames.SUB, "actor1"));
		OAuth2TokenExchangeActor actor2 = new OAuth2TokenExchangeActor(
				Map.of(JwtClaimNames.ISS, "issuer-2", JwtClaimNames.SUB, "actor2"));
		OAuth2TokenExchangeCompositeAuthenticationToken authentication = new OAuth2TokenExchangeCompositeAuthenticationToken(
				subject, List.of(actor1, actor2));
		String json = this.objectMapper.writeValueAsString(authentication);
		assertThat(this.objectMapper.readValue(json, OAuth2TokenExchangeCompositeAuthenticationToken.class))
			.isEqualTo(authentication);
	}

}
