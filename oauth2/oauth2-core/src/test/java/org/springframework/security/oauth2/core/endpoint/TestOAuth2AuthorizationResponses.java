/*
 * Copyright 2002-2018 the original author or authors.
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

/**
 * @author Rob Winch
 * @since 5.1
 */
public final class TestOAuth2AuthorizationResponses {

	private TestOAuth2AuthorizationResponses() {
	}

	public static OAuth2AuthorizationResponse.Builder success() {
		return OAuth2AuthorizationResponse.success("authorization-code").state("state")
				.redirectUri("https://example.com/authorize/oauth2/code/registration-id");
	}

	public static OAuth2AuthorizationResponse.Builder error() {
		return OAuth2AuthorizationResponse.error("error")
				.redirectUri("https://example.com/authorize/oauth2/code/registration-id")
				.errorUri("https://example.com/error");
	}

}
