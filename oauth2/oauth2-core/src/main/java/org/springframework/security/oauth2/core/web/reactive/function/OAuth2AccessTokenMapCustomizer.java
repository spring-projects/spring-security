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

package org.springframework.security.oauth2.core.web.reactive.function;

import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;

import java.util.Map;

/**
 * Provides a way to customize the response {@link Map}
 * before it gets decoded as {@link OAuth2AccessTokenResponse}
 *
 * @author Bishoy Basily
 * @since 5.6
 */
public interface OAuth2AccessTokenMapCustomizer {

	default Map<String, Object> customizeOAuth2AccessTokenMap(Map<String, Object> map) {
		return map;
	}

}
