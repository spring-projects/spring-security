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

package org.springframework.security.web.authentication;

import org.springframework.http.converter.GenericHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.GsonHttpMessageConverter;
import org.springframework.http.converter.json.JacksonJsonHttpMessageConverter;
import org.springframework.http.converter.json.JsonbHttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.util.ClassUtils;

/**
 * Utility methods for {@link HttpMessageConverter}'s.
 *
 * @author Rob Winch
 * @since 7.0.4
 */
final class HttpMessageConverters {

	private static final boolean jacksonPresent;

	private static final boolean jackson2Present;

	private static final boolean gsonPresent;

	private static final boolean jsonbPresent;

	private static final String JSON_MAPPER = "tools.jackson.databind.json.JsonMapper";

	private static final String OBJECT_MAPPER = "com.fasterxml.jackson.databind.ObjectMapper";

	private static final String JSON_GENERATOR = "com.fasterxml.jackson.core.JsonGenerator";

	private static final String GSON = "com.google.gson.Gson";

	private static final String JSONB = "jakarta.json.bind.Jsonb";

	static {
		ClassLoader classLoader = HttpMessageConverters.class.getClassLoader();
		jacksonPresent = ClassUtils.isPresent(JSON_MAPPER, classLoader);
		jackson2Present = ClassUtils.isPresent(OBJECT_MAPPER, classLoader)
				&& ClassUtils.isPresent(JSON_GENERATOR, classLoader);
		gsonPresent = ClassUtils.isPresent(GSON, classLoader);
		jsonbPresent = ClassUtils.isPresent(JSONB, classLoader);
	}

	private HttpMessageConverters() {
	}

	/**
	 * Gets the {@link GenericHttpMessageConverterAdapter} to use for JSON.
	 * @return the {@link GenericHttpMessageConverterAdapter} to use.
	 */
	@SuppressWarnings("removal")
	static GenericHttpMessageConverter<Object> getJsonMessageConverter() {
		if (jacksonPresent) {
			return new GenericHttpMessageConverterAdapter<>(new JacksonJsonHttpMessageConverter());
		}
		if (jackson2Present) {
			return new MappingJackson2HttpMessageConverter();
		}
		if (gsonPresent) {
			return new GsonHttpMessageConverter();
		}
		if (jsonbPresent) {
			return new JsonbHttpMessageConverter();
		}
		throw new IllegalStateException(
				"Cannot find JSON Converter on the classpath. Add one following classes to the classpath "
						+ String.join(", ", JSON_MAPPER, OBJECT_MAPPER, JSON_MAPPER, GSON, JSONB));
	}

}
