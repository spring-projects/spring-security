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

package org.springframework.security.jackson;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

/**
 * This mixin class helps in serialize/deserialize
 * {@link org.springframework.security.authentication.BadCredentialsException} class.
 *
 * @author Sebastien Deleuze
 * @author Yannick Lombardi
 * @since 7.0
 * @see CoreJacksonModule
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonIgnoreProperties({ "cause", "stackTrace", "authenticationRequest" })
class BadCredentialsExceptionMixin {

	/**
	 * Constructor used by Jackson to create
	 * {@link org.springframework.security.authentication.BadCredentialsException} object.
	 * @param message the detail message
	 */
	@JsonCreator
	BadCredentialsExceptionMixin(@JsonProperty("message") String message) {
	}

}
