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

import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.Assert;

import java.io.IOException;
import java.util.function.Function;

/**
 * A <code>Function</code> that converts a {@link ClientHttpResponse}
 * to a custom type of {@link OAuth2User}, as supplied via the constructor.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see OAuth2User
 * @see ClientHttpResponse
 */
public final class CustomOAuth2UserConverter<R extends OAuth2User> implements Function<ClientHttpResponse, R> {
	private final HttpMessageConverter jackson2HttpMessageConverter = new MappingJackson2HttpMessageConverter();
	private final Class<R> customType;

	public CustomOAuth2UserConverter(Class<R> customType) {
		Assert.notNull(customType, "customType cannot be null");
		this.customType = customType;
	}

	@Override
	public R apply(ClientHttpResponse clientHttpResponse) {
		R user;

		try {
			user = (R) this.jackson2HttpMessageConverter.read(this.customType, clientHttpResponse);
		} catch (IOException ex) {
			throw new IllegalArgumentException("An error occurred reading the UserInfo response: " + ex.getMessage(), ex);
		}

		return user;
	}
}
