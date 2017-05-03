/*
 * Copyright 2012-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.client.user.converter;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.io.IOException;

/**
 * An implementation of a {@link Converter} that converts a {@link ClientHttpResponse}
 * to a custom type of {@link OAuth2User}, as supplied via the constructor.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see OAuth2User
 * @see ClientHttpResponse
 */
public final class CustomOAuth2UserConverter<T extends OAuth2User> implements Converter<ClientHttpResponse, T> {
	private final HttpMessageConverter jackson2HttpMessageConverter = new MappingJackson2HttpMessageConverter();
	private final Class<T> customType;

	public CustomOAuth2UserConverter(Class<T> customType) {
		this.customType = customType;
	}

	@Override
	public T convert(ClientHttpResponse clientHttpResponse) {
		T user;

		try {
			user = (T) this.jackson2HttpMessageConverter.read(this.customType, clientHttpResponse);
		} catch (IOException ex) {
			throw new IllegalArgumentException("An error occurred reading the UserInfo response: " + ex.getMessage(), ex);
		}

		return user;
	}
}
