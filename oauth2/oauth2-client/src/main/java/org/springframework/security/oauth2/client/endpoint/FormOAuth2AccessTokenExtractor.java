/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.oauth2.client.endpoint;

import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.ResponseExtractor;

import java.io.IOException;
import java.util.*;

/**
 * Created by XYUU <xyuu@xyuu.net> on 2018/4/23.
 */
public class FormOAuth2AccessTokenExtractor implements ResponseExtractor<OAuth2AccessTokenResponse> {

	public static final String NAME = "form";

	private final FormHttpMessageConverter delegateMessageConverter;

	public FormOAuth2AccessTokenExtractor(FormHttpMessageConverter delegateMessageConverter) {
		this.delegateMessageConverter = delegateMessageConverter;
	}

	@Override
	public OAuth2AccessTokenResponse extractData(ClientHttpResponse response) throws IOException {
		MultiValueMap<String, String> data = delegateMessageConverter.read(null, response);
		String tokenValue = null;
		String tokenType = null;
		String refreshToken = null;
		Long expiresIn = 0L;
		Set<String> scope = null;
		Map<String, Object> additionalInformation = new LinkedHashMap<>();
		for (Map.Entry<String, List<String>> entry : data.entrySet()) {
			String name = entry.getKey();
			List<String> values = entry.getValue();
			switch (name) {
				case OAuth2ParameterNames.ACCESS_TOKEN:
					tokenValue = values.get(0);
					break;
				case OAuth2ParameterNames.TOKEN_TYPE:
					tokenType = values.get(0);
					break;
				case OAuth2ParameterNames.REFRESH_TOKEN:
					refreshToken = values.get(0);
					break;
				case OAuth2ParameterNames.EXPIRES_IN:
					expiresIn = Long.valueOf(values.get(0));
					break;
				case OAuth2ParameterNames.SCOPE:
					if (values.size() > 1) {
						scope = new TreeSet<>(values);
					} else {
						String value = values.get(0);
						if (value != null && value.trim().length() > 0) {
							// the spec says the scope is separated by spaces
							String[] tokens = value.split("[\\s+]");
							scope = new TreeSet<>(Arrays.asList(tokens));
						}
					}
					break;
				default:
					additionalInformation.put(name, values.get(0));
			}
		}
		return OAuth2AccessTokenResponse.withToken(tokenValue)
				.tokenType(OAuth2AccessToken.TokenType.BEARER)
				.expiresIn(expiresIn)
				.scopes(scope)
				.additionalParameters(additionalInformation).build();
	}
}
