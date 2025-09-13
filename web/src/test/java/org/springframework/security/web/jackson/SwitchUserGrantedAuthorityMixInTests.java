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

package org.springframework.security.web.jackson;

import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.skyscreamer.jsonassert.JSONAssert;
import tools.jackson.databind.json.JsonMapper;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.jackson.CoreJacksonModule;
import org.springframework.security.jackson.SecurityJacksonModules;
import org.springframework.security.jackson.SimpleGrantedAuthorityMixinTests;
import org.springframework.security.web.authentication.switchuser.SwitchUserGrantedAuthority;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Markus Heiden
 * @since 6.3
 */
public class SwitchUserGrantedAuthorityMixInTests {

	// language=JSON
	private static final String SWITCH_JSON = """
			{
				"@class": "org.springframework.security.web.authentication.switchuser.SwitchUserGrantedAuthority",
				"role": "switched",
				"source": {
					"@class": "org.springframework.security.authentication.UsernamePasswordAuthenticationToken",
					"principal": "principal",
					"credentials": "credentials",
					"authenticated": true,
					"details": null,
					"authorities": %s
				}
			}
			""".formatted(SimpleGrantedAuthorityMixinTests.AUTHORITIES_ARRAYLIST_JSON);

	private Authentication source;

	static Stream<Arguments> mappers() {
		ClassLoader classLoader = SwitchUserGrantedAuthorityMixInTests.class.getClassLoader();
		JsonMapper securityJackson2ModulesMapper = JsonMapper.builder()
			.addModules(SecurityJacksonModules.getModules(classLoader))
			.build();

		JsonMapper webJackson2ModuleMapper = JsonMapper.builder()
			.addModule(new CoreJacksonModule())
			.addModule(new WebJacksonModule())
			.build();

		JsonMapper webServletJackson2ModuleMapper = JsonMapper.builder()
			.addModule(new CoreJacksonModule())
			.addModule(new WebServletJacksonModule())
			.build();

		return Stream.of(Arguments.of(securityJackson2ModulesMapper), Arguments.of(webJackson2ModuleMapper),
				Arguments.of(webServletJackson2ModuleMapper));
	}

	@BeforeEach
	public void setUp() {
		this.source = new UsernamePasswordAuthenticationToken("principal", "credentials",
				AuthorityUtils.createAuthorityList("ROLE_USER"));
	}

	@ParameterizedTest
	@MethodSource("mappers")
	public void serializeWhenPrincipalCredentialsAuthoritiesThenSuccess(JsonMapper mapper) throws Exception {
		SwitchUserGrantedAuthority expected = new SwitchUserGrantedAuthority("switched", this.source);
		String serializedJson = mapper.writeValueAsString(expected);
		JSONAssert.assertEquals(SWITCH_JSON, serializedJson, true);
	}

	@ParameterizedTest
	@MethodSource("mappers")
	public void deserializeWhenSourceIsUsernamePasswordAuthenticationTokenThenSuccess(JsonMapper mapper)
			throws Exception {
		SwitchUserGrantedAuthority deserialized = mapper.readValue(SWITCH_JSON, SwitchUserGrantedAuthority.class);
		assertThat(deserialized).isNotNull();
		assertThat(deserialized.getAuthority()).isEqualTo("switched");
		assertThat(deserialized.getSource()).isEqualTo(this.source);
	}

}
