/*
 * Copyright 2002-2020 the original author or authors.
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

/**
 * @author Rob Winch
 * @since 5.1
 */
public final class TestOAuth2AuthorizationRequests {

	private TestOAuth2AuthorizationRequests() {
	}

	public static OAuth2AuthorizationRequest.Builder request() {
		String registrationId = "registration-id";
		String clientId = "client-id";
		Map<String, Object> attributes = new HashMap<>();
		attributes.put(OAuth2ParameterNames.REGISTRATION_ID, registrationId);
		return OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri("https://example.com/login/oauth/authorize").clientId(clientId)
				.redirectUri("https://example.com/authorize/oauth2/code/registration-id").state("state")
				.attributes(attributes);
	}

	public static OAuth2AuthorizationRequest.Builder oidcRequest() {
		return request().scope("openid");
	}

}
