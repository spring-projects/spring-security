/*
 * Copyright 2015-2017 the original author or authors.
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


package org.springframework.security.jackson2;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonIgnoreType;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Before;
import org.junit.Test;

import java.lang.annotation.*;
import java.util.HashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
* @author Rob Winch
* @since 5.0
*/
public class SecurityJackson2ModulesTests {
	private ObjectMapper mapper;

	@Before
	public void setup() {
		mapper = new ObjectMapper();
		SecurityJackson2Modules.enableDefaultTyping(mapper);
	}

	@Test
	public void readValueWhenNotWhitelistedOrMappedThenThrowsException() throws Exception {
		String content = "{\"@class\":\"org.springframework.security.jackson2.SecurityJackson2ModulesTests$NotWhitelisted\",\"property\":\"bar\"}";
		try {
			mapper.readValue(content, Object.class);
			fail("Expected Exception");
		} catch(RuntimeException e) {
			assertThat(e).hasMessageContaining("whitelisted");
		}
	}

	@Test
	public void readValueWhenExplicitDefaultTypingAfterSecuritySetupThenReadsAsSpecificType() throws Exception {
		mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL, JsonTypeInfo.As.PROPERTY);
		String content = "{\"@class\":\"org.springframework.security.jackson2.SecurityJackson2ModulesTests$NotWhitelisted\",\"property\":\"bar\"}";

		assertThat(mapper.readValue(content, Object.class)).isInstanceOf(NotWhitelisted.class);
	}

	@Test
	public void readValueWhenExplicitDefaultTypingBeforeSecuritySetupThenReadsAsSpecificType() throws Exception {
		mapper = new ObjectMapper();
		mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL, JsonTypeInfo.As.PROPERTY);
		SecurityJackson2Modules.enableDefaultTyping(mapper);
		String content = "{\"@class\":\"org.springframework.security.jackson2.SecurityJackson2ModulesTests$NotWhitelisted\",\"property\":\"bar\"}";

		assertThat(mapper.readValue(content, Object.class)).isInstanceOf(NotWhitelisted.class);
	}

	@Test
	public void readValueWhenAnnotatedThenReadsAsSpecificType() throws Exception {
		String content = "{\"@class\":\"org.springframework.security.jackson2.SecurityJackson2ModulesTests$NotWhitelistedButAnnotated\",\"property\":\"bar\"}";

		assertThat(mapper.readValue(content, Object.class)).isInstanceOf(NotWhitelistedButAnnotated.class);
	}

	@Test
	public void readValueWhenMixinProvidedThenReadsAsSpecificType() throws Exception {
		mapper.addMixIn(NotWhitelisted.class, NotWhitelistedMixin.class);
		String content = "{\"@class\":\"org.springframework.security.jackson2.SecurityJackson2ModulesTests$NotWhitelisted\",\"property\":\"bar\"}";

		assertThat(mapper.readValue(content, Object.class)).isInstanceOf(NotWhitelisted.class);
	}

	@Test
	public void readValueWhenHashMapThenReadsAsSpecificType() throws Exception {
		mapper.addMixIn(NotWhitelisted.class, NotWhitelistedMixin.class);
		String content = "{\"@class\":\"java.util.HashMap\"}";

		assertThat(mapper.readValue(content, Object.class)).isInstanceOf(HashMap.class);
	}

	@Target({ ElementType.TYPE, ElementType.ANNOTATION_TYPE })
	@Retention(RetentionPolicy.RUNTIME)
	@Documented
	public @interface NotJacksonAnnotation {}

	@NotJacksonAnnotation
	static class NotWhitelisted {
		private String property = "bar";

		public String getProperty() {
			return property;
		}

		public void setProperty(String property) {
		}
	}

	@JsonIgnoreType(false)
	static class NotWhitelistedButAnnotated {
		private String property = "bar";

		public String getProperty() {
			return property;
		}

		public void setProperty(String property) {
		}
	}

	@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY)
	@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, getterVisibility = JsonAutoDetect.Visibility.NONE,
		isGetterVisibility = JsonAutoDetect.Visibility.NONE)
	@JsonIgnoreProperties(ignoreUnknown = true)
	abstract class NotWhitelistedMixin {

	}
}
