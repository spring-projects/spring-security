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

package org.springframework.security.jackson2;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.HashMap;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonIgnoreType;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * @author Rob Winch
 * @since 5.0
 */
@SuppressWarnings("removal")
public class SecurityJackson2ModulesTests {

	private ObjectMapper mapper;

	@BeforeEach
	public void setup() {
		this.mapper = new ObjectMapper();
		SecurityJackson2Modules.enableDefaultTyping(this.mapper);
	}

	@Test
	public void readValueWhenNotAllowedOrMappedThenThrowsException() {
		String content = "{\"@class\":\"org.springframework.security.jackson2.SecurityJackson2ModulesTests$NotAllowlisted\",\"property\":\"bar\"}";
		// @formatter:off
		assertThatExceptionOfType(Exception.class)
				.isThrownBy(() -> this.mapper.readValue(content, Object.class))
				.withStackTraceContaining("allowlist");
		// @formatter:on
	}

	@Test
	public void readValueWhenExplicitDefaultTypingAfterSecuritySetupThenReadsAsSpecificType() throws Exception {
		this.mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL, JsonTypeInfo.As.PROPERTY);
		String content = "{\"@class\":\"org.springframework.security.jackson2.SecurityJackson2ModulesTests$NotAllowlisted\",\"property\":\"bar\"}";
		assertThat(this.mapper.readValue(content, Object.class)).isInstanceOf(NotAllowlisted.class);
	}

	@Test
	public void readValueWhenExplicitDefaultTypingBeforeSecuritySetupThenReadsAsSpecificType() throws Exception {
		this.mapper = new ObjectMapper();
		this.mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL, JsonTypeInfo.As.PROPERTY);
		SecurityJackson2Modules.enableDefaultTyping(this.mapper);
		String content = "{\"@class\":\"org.springframework.security.jackson2.SecurityJackson2ModulesTests$NotAllowlisted\",\"property\":\"bar\"}";
		assertThat(this.mapper.readValue(content, Object.class)).isInstanceOf(NotAllowlisted.class);
	}

	@Test
	public void readValueWhenAnnotatedThenReadsAsSpecificType() throws Exception {
		String content = "{\"@class\":\"org.springframework.security.jackson2.SecurityJackson2ModulesTests$NotAllowlistedButAnnotated\",\"property\":\"bar\"}";
		assertThat(this.mapper.readValue(content, Object.class)).isInstanceOf(NotAllowlistedButAnnotated.class);
	}

	@Test
	public void readValueWhenMixinProvidedThenReadsAsSpecificType() throws Exception {
		this.mapper.addMixIn(NotAllowlisted.class, NotAllowlistedMixin.class);
		String content = "{\"@class\":\"org.springframework.security.jackson2.SecurityJackson2ModulesTests$NotAllowlisted\",\"property\":\"bar\"}";
		assertThat(this.mapper.readValue(content, Object.class)).isInstanceOf(NotAllowlisted.class);
	}

	@Test
	public void readValueWhenHashMapThenReadsAsSpecificType() throws Exception {
		this.mapper.addMixIn(NotAllowlisted.class, NotAllowlistedMixin.class);
		String content = "{\"@class\":\"java.util.HashMap\"}";
		assertThat(this.mapper.readValue(content, Object.class)).isInstanceOf(HashMap.class);
	}

	@Target({ ElementType.TYPE, ElementType.ANNOTATION_TYPE })
	@Retention(RetentionPolicy.RUNTIME)
	@Documented
	public @interface NotJacksonAnnotation {

	}

	@NotJacksonAnnotation
	static class NotAllowlisted {

		private String property = "bar";

		String getProperty() {
			return this.property;
		}

		void setProperty(String property) {
		}

	}

	@JsonIgnoreType(false)
	static class NotAllowlistedButAnnotated {

		private String property = "bar";

		String getProperty() {
			return this.property;
		}

		void setProperty(String property) {
		}

	}

	@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY)
	@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, getterVisibility = JsonAutoDetect.Visibility.NONE,
			isGetterVisibility = JsonAutoDetect.Visibility.NONE)
	@JsonIgnoreProperties(ignoreUnknown = true)
	abstract class NotAllowlistedMixin {

	}

}
