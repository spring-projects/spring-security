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

package org.springframework.security.jackson2;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

/**
 * This mixin class helps in serialize/deserialize
 * {@link org.springframework.security.authentication.BadCredentialsException} class. To
 * use this class you need to register it with
 * {@link com.fasterxml.jackson.databind.ObjectMapper}.
 *
 * <pre>
 *     ObjectMapper mapper = new ObjectMapper();
 *     mapper.registerModule(new CoreJackson2Module());
 * </pre>
 *
 * <i>Note: This class will save TypeInfo (full class name) into a property
 * called @class</i> <i>The cause and stackTrace are ignored in the serialization.</i>
 *
 * @author Yannick Lombardi
 * @since 5.0
 * @see CoreJackson2Module
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY)
@JsonIgnoreProperties(ignoreUnknown = true, value = { "cause", "stackTrace" })
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
