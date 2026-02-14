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

package org.springframework.security.jackson;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JacksonModule;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class SecurityJacksonModulesTests {

	@Test
	public void addModulesWithNoTypeValidatorBuilder() {
		ClassLoader loader = getClass().getClassLoader();
		List<JacksonModule> modules = SecurityJacksonModules.getModules(loader);
		JsonMapper mapper = JsonMapper.builder().addModules(modules).build();
		User user = new User("user", null, List.of(new SimpleGrantedAuthority("SCOPE_message:read")));
		String json = mapper.writeValueAsString(user);
		User deserializedUer = mapper.readerFor(User.class).readValue(json);
		assertThat(deserializedUer).isEqualTo(user);
	}

	@Test
	public void addModulesWithDefaultTypeValidatorBuilder() {
		ClassLoader loader = getClass().getClassLoader();
		List<JacksonModule> modules = SecurityJacksonModules.getModules(loader,
				BasicPolymorphicTypeValidator.builder());
		JsonMapper mapper = JsonMapper.builder().addModules(modules).build();
		User user = new User("user", null, List.of(new SimpleGrantedAuthority("SCOPE_message:read")));
		String json = mapper.writeValueAsString(user);
		User deserializedUer = mapper.readerFor(User.class).readValue(json);
		assertThat(deserializedUer).isEqualTo(user);
	}

	@Test
	public void addModulesWithCustomTypeValidator() {
		ClassLoader loader = getClass().getClassLoader();
		BasicPolymorphicTypeValidator.Builder builder = BasicPolymorphicTypeValidator.builder()
			.allowIfSubType(TestGrantedAuthority.class);
		List<JacksonModule> modules = SecurityJacksonModules.getModules(loader, builder);
		JsonMapper mapper = JsonMapper.builder().addModules(modules).build();
		User user = new User("user", null, List.of(new TestGrantedAuthority()));
		String json = mapper.writeValueAsString(user);
		User deserializedUer = mapper.readerFor(User.class).readValue(json);
		assertThat(deserializedUer).isEqualTo(user);
	}

	@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
	private static class TestGrantedAuthority implements GrantedAuthority {

		@Override
		public String getAuthority() {
			return "test";
		}

	}

	@Test
	public void readDatesAsTimestampsIsDisabledThenSerializeAsIsoString() throws Exception {
		ClassLoader loader = getClass().getClassLoader();
		List<tools.jackson.databind.JacksonModule> modules = SecurityJacksonModules.getModules(loader);

		JsonMapper mapper = JsonMapper.builder()
				.addModules(modules)
				.disable(tools.jackson.databind.cfg.DateTimeFeature.WRITE_DATES_AS_TIMESTAMPS)
				.build();

		java.time.LocalDateTime date = java.time.LocalDateTime.of(2026, 1, 25, 12, 0);

		String json = mapper.writeValueAsString(date);

		assertThat(json).isEqualTo("\"2026-01-25T12:00:00\"");
	}

}
