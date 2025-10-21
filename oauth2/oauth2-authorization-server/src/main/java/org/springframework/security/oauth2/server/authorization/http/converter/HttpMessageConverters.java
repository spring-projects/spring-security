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

package org.springframework.security.oauth2.server.authorization.http.converter;

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
 * @author Joe Grandja
 * @author l uamas
 * @since 7.0
 */
final class HttpMessageConverters {

	private static final boolean jacksonPresent;

	private static final boolean jackson2Present;

	private static final boolean gsonPresent;

	private static final boolean jsonbPresent;

	static {
		ClassLoader classLoader = HttpMessageConverters.class.getClassLoader();
		jacksonPresent = ClassUtils.isPresent("tools.jackson.databind.json.JsonMapper", classLoader);
		jackson2Present = ClassUtils.isPresent("com.fasterxml.jackson.databind.ObjectMapper", classLoader)
				&& ClassUtils.isPresent("com.fasterxml.jackson.core.JsonGenerator", classLoader);
		gsonPresent = ClassUtils.isPresent("com.google.gson.Gson", classLoader);
		jsonbPresent = ClassUtils.isPresent("jakarta.json.bind.Jsonb", classLoader);
	}

	private HttpMessageConverters() {
	}

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
		return null;
	}

}
