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

package org.springframework.security.web.webauthn.jackson;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;
import tools.jackson.databind.JacksonModule;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.jackson.SecurityJacksonModules;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthentication;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link WebAuthnAuthenticationMixin} and
 * {@link ImmutablePublicKeyCredentialUserEntityMixin} with polymorphic type handling.
 *
 * <p>
 * This test class is separate from {@link JacksonTests} because it requires a
 * {@link JsonMapper} configured with {@link SecurityJacksonModules} to enable polymorphic
 * type information ({@code @class}). {@link JacksonTests} uses a {@link JsonMapper}
 * configured only with {@link WebauthnJacksonModule}, and its existing custom serializers
 * are not compatible with the automatic inclusion of type information enabled by
 * {@link SecurityJacksonModules}.
 *
 * @author Toshiaki Maki
 * @since 7.1
 */
class WebAuthnAuthenticationMixinTests {

	private JsonMapper mapper;

	@BeforeEach
	void setup() {
		ClassLoader classLoader = getClass().getClassLoader();
		WebauthnJacksonModule webauthnJacksonModule = new WebauthnJacksonModule();
		BasicPolymorphicTypeValidator.Builder typeValidatorBuilder = BasicPolymorphicTypeValidator.builder();
		webauthnJacksonModule.configurePolymorphicTypeValidator(typeValidatorBuilder);
		List<JacksonModule> modules = SecurityJacksonModules.getModules(classLoader, typeValidatorBuilder);
		modules.add(webauthnJacksonModule);
		this.mapper = JsonMapper.builder().addModules(modules).build();
	}

	@Test
	void writeWebAuthnAuthentication() throws Exception {
		ImmutablePublicKeyCredentialUserEntity principal = (ImmutablePublicKeyCredentialUserEntity) ImmutablePublicKeyCredentialUserEntity
			.builder()
			.name("user@example.localhost")
			.id(Bytes.fromBase64("oWJtkJ6vJ_m5b84LB4_K7QKTCTEwLIjCh4tFMCGHO4w"))
			.displayName("User")
			.build();
		WebAuthnAuthentication authentication = new WebAuthnAuthentication(principal,
				List.of(new SimpleGrantedAuthority("ROLE_USER")));

		String json = this.mapper.writeValueAsString(authentication);

		String expected = """
				{
					"@class": "org.springframework.security.web.webauthn.authentication.WebAuthnAuthentication",
					"principal": {
						"@class": "org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity",
						"name": "user@example.localhost",
						"id": "oWJtkJ6vJ_m5b84LB4_K7QKTCTEwLIjCh4tFMCGHO4w",
						"displayName": "User"
					},
					"authorities": ["java.util.Collections$UnmodifiableRandomAccessList", [
						{
							"@class": "org.springframework.security.core.authority.SimpleGrantedAuthority",
							"authority": "ROLE_USER"
						}
					]]
				}
				""";
		JSONAssert.assertEquals(expected, json, false);
		assertThat(json).doesNotContain("\"authenticated\"");
	}

	@Test
	void readWebAuthnAuthentication() throws Exception {
		String json = """
				{
					"@class": "org.springframework.security.web.webauthn.authentication.WebAuthnAuthentication",
					"principal": {
						"@class": "org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity",
						"name": "user@example.localhost",
						"id": "oWJtkJ6vJ_m5b84LB4_K7QKTCTEwLIjCh4tFMCGHO4w",
						"displayName": "User"
					},
					"authorities": ["java.util.Collections$UnmodifiableRandomAccessList", [
						{
							"@class": "org.springframework.security.core.authority.SimpleGrantedAuthority",
							"authority": "ROLE_USER"
						}
					]]
				}
				""";
		ImmutablePublicKeyCredentialUserEntity expectedPrincipal = (ImmutablePublicKeyCredentialUserEntity) ImmutablePublicKeyCredentialUserEntity
			.builder()
			.name("user@example.localhost")
			.id(Bytes.fromBase64("oWJtkJ6vJ_m5b84LB4_K7QKTCTEwLIjCh4tFMCGHO4w"))
			.displayName("User")
			.build();
		WebAuthnAuthentication expected = new WebAuthnAuthentication(expectedPrincipal,
				List.of(new SimpleGrantedAuthority("ROLE_USER")));

		WebAuthnAuthentication authentication = this.mapper.readValue(json, WebAuthnAuthentication.class);

		assertThat(authentication).usingRecursiveComparison().isEqualTo(expected);
	}

}
