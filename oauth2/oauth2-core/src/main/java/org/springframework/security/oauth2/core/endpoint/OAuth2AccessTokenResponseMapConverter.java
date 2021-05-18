/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.oauth2.core.endpoint;

import java.util.HashMap;
import java.util.Map;

import org.springframework.core.convert.converter.Converter;

/**
 * A {@link Converter} that converts the provided {@link OAuth2AccessTokenResponse} to a
 * {@code Map} representation of the OAuth 2.0 Access Token Response parameters.
 *
 * @deprecated Use {@link DefaultOAuth2AccessTokenResponseMapConverter} instead
 * @author Joe Grandja
 * @author Nikita Konev
 * @since 5.3
 */
@Deprecated
public final class OAuth2AccessTokenResponseMapConverter
		implements Converter<OAuth2AccessTokenResponse, Map<String, String>> {

	private final Converter<OAuth2AccessTokenResponse, Map<String, Object>> delegate = new DefaultOAuth2AccessTokenResponseMapConverter();

	@Override
	public Map<String, String> convert(OAuth2AccessTokenResponse tokenResponse) {
		Map<String, String> stringTokenResponseParameters = new HashMap<>();
		this.delegate.convert(tokenResponse)
				.forEach((key, value) -> stringTokenResponseParameters.put(key, String.valueOf(value)));
		return stringTokenResponseParameters;
	}

}
