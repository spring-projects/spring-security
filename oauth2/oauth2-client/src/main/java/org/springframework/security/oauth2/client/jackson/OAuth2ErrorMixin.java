/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.oauth2.client.jackson;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

import org.springframework.security.oauth2.core.OAuth2Error;

/**
 * This mixin class is used to serialize/deserialize {@link OAuth2Error} as part of
 * {@link org.springframework.security.oauth2.core.OAuth2AuthenticationException}.
 *
 * @author Sebastien Deleuze
 * @author Dennis Neufeld
 * @since 7.0
 * @see OAuth2Error
 * @see OAuth2AuthenticationExceptionMixin
 * @see OAuth2ClientJacksonModule
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, getterVisibility = JsonAutoDetect.Visibility.NONE,
		isGetterVisibility = JsonAutoDetect.Visibility.NONE)
abstract class OAuth2ErrorMixin {

	@JsonCreator
	OAuth2ErrorMixin(@JsonProperty("errorCode") String errorCode, @JsonProperty("description") String description,
			@JsonProperty("uri") String uri) {
	}

}
