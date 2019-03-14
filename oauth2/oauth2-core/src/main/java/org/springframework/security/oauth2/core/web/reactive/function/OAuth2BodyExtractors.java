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

package org.springframework.security.oauth2.core.web.reactive.function;

import org.springframework.http.ReactiveHttpInputMessage;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.web.reactive.function.BodyExtractor;
import reactor.core.publisher.Mono;

/**
 * Static factory methods for OAuth2 {@link BodyExtractor} implementations.
 * @author Rob Winch
 * @since 5.1
 */
public abstract class OAuth2BodyExtractors {

	/**
	 * Extractor to decode an {@link OAuth2AccessTokenResponse}
	 * @return a BodyExtractor for {@link OAuth2AccessTokenResponse}
	 */
	public static BodyExtractor<Mono<OAuth2AccessTokenResponse>, ReactiveHttpInputMessage> oauth2AccessTokenResponse() {
		return new OAuth2AccessTokenResponseBodyExtractor();
	}

	private OAuth2BodyExtractors() {}
}
