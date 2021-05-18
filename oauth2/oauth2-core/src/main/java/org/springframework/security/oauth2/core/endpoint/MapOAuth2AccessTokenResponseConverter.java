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

import java.util.Map;

import org.springframework.core.convert.converter.Converter;

/**
 * A {@link Converter} that converts the provided OAuth 2.0 Access Token Response
 * parameters to an {@link OAuth2AccessTokenResponse}.
 *
 * @deprecated Use {@link DefaultMapOAuth2AccessTokenResponseConverter} instead
 * @author Joe Grandja
 * @author Nikita Konev
 * @since 5.3
 */
@Deprecated
public final class MapOAuth2AccessTokenResponseConverter
		implements Converter<Map<String, String>, OAuth2AccessTokenResponse> {

	private final Converter<Map<String, ?>, OAuth2AccessTokenResponse> delegate = new DefaultMapOAuth2AccessTokenResponseConverter();

	@Override
	public OAuth2AccessTokenResponse convert(Map<String, String> tokenResponseParameters) {
		return this.delegate.convert(tokenResponseParameters);
	}

}
