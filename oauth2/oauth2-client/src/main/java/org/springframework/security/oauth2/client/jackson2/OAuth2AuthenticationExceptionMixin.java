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

package org.springframework.security.oauth2.client.jackson2;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

/**
 * This mixin class is used to serialize/deserialize
 * {@link OAuth2AuthenticationException}.
 *
 * @author Dennis Neufeld
 * @author Steve Riesenberg
 * @since 5.3.4
 * @see OAuth2AuthenticationException
 * @see OAuth2ClientJackson2Module
 * @deprecated as of 7.0 in favor of
 * {@code org.springframework.security.oauth2.client.jackson.OAuth2AuthenticationExceptionMixin}
 * based on Jackson 3
 */
@Deprecated(forRemoval = true)
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.NONE, getterVisibility = JsonAutoDetect.Visibility.NONE,
		isGetterVisibility = JsonAutoDetect.Visibility.NONE)
@JsonIgnoreProperties(ignoreUnknown = true, value = { "cause", "stackTrace", "suppressedExceptions" })
abstract class OAuth2AuthenticationExceptionMixin {

	@JsonProperty("error")
	abstract OAuth2Error getError();

	@JsonProperty("detailMessage")
	abstract String getMessage();

	@JsonCreator
	OAuth2AuthenticationExceptionMixin(@JsonProperty("error") OAuth2Error error,
			@JsonProperty("detailMessage") String message) {
	}

}
