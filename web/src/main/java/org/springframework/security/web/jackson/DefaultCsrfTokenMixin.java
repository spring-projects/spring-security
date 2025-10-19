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

package org.springframework.security.web.jackson;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

/**
 * Jackson mixin class to serialize/deserialize
 * {@link org.springframework.security.web.csrf.DefaultCsrfToken} serialization support.
 *
 * @author Sebastien Deleuze
 * @author Jitendra Singh
 * @since 7.0
 * @see WebJacksonModule
 * @see org.springframework.security.jackson.SecurityJacksonModules
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
class DefaultCsrfTokenMixin {

	/**
	 * JsonCreator constructor needed by Jackson to create
	 * {@link org.springframework.security.web.csrf.DefaultCsrfToken} object.
	 * @param headerName the name of the header
	 * @param parameterName the parameter name
	 * @param token the CSRF token value
	 */
	@JsonCreator
	DefaultCsrfTokenMixin(@JsonProperty("headerName") String headerName,
			@JsonProperty("parameterName") String parameterName, @JsonProperty("token") String token) {
	}

}
