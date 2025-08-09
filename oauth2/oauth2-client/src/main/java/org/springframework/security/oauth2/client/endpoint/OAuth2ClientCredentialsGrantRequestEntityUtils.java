/*
 * Copyright 2025 the original author or authors.
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

package org.springframework.security.oauth2.client.endpoint;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.StringJoiner;

import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

/**
 * Utility methods for the OAuth 2.0 Client Credentials Grant.
 *
 * @author Hyunjoon Kim
 * @since 6.5
 */
final class OAuth2ClientCredentialsGrantRequestEntityUtils {

	private OAuth2ClientCredentialsGrantRequestEntityUtils() {
	}

	static String encodeFormData(MultiValueMap<String, String> parameters) {
		StringJoiner result = new StringJoiner("&");
		parameters.forEach((key, values) -> {
			for (String value : values) {
				result.add(encodeFormParameter(key, value));
			}
		});
		return result.toString();
	}

	private static String encodeFormParameter(String name, String value) {
		if (!StringUtils.hasText(value)) {
			return urlEncode(name);
		}
		
		// Special handling for client_secret to preserve Base64 padding
		if (OAuth2ParameterNames.CLIENT_SECRET.equals(name) && value.endsWith("=")) {
			// For client secrets ending with '=', don't encode the padding character
			int lastEqualIndex = value.lastIndexOf('=');
			String beforePadding = value.substring(0, lastEqualIndex);
			String padding = value.substring(lastEqualIndex);
			return urlEncode(name) + "=" + urlEncode(beforePadding) + padding;
		}
		
		return urlEncode(name) + "=" + urlEncode(value);
	}

	private static String urlEncode(String value) {
		try {
			return URLEncoder.encode(value, StandardCharsets.UTF_8.name());
		}
		catch (UnsupportedEncodingException ex) {
			// Should never happen with UTF-8
			throw new IllegalArgumentException(ex);
		}
	}

}