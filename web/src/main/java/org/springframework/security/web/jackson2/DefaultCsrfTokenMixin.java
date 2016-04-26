/*
 * Copyright 2015-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.jackson2;

import com.fasterxml.jackson.annotation.*;

/**
 * Jackson mixin class to serialize/deserialize {@link org.springframework.security.web.csrf.DefaultCsrfToken}
 * serialization support.
 *
 * <pre>
 * 	ObjectMapper mapper = new ObjectMapper();
 *	mapper.addMixIn(DefaultCsrfToken.class, DefaultCsrfTokenMixin.class);
 * </pre>
 *
 * @author Jitendra Singh
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
public class DefaultCsrfTokenMixin {

	/**
	 * JsonCreator constructor needed by Jackson to create {@link org.springframework.security.web.csrf.DefaultCsrfToken}
	 * object.
	 *
	 * @param headerName
	 * @param parameterName
	 * @param token
	 */
	@JsonCreator
	public DefaultCsrfTokenMixin(@JsonProperty("headerName") String headerName,
								@JsonProperty("parameterName") String parameterName, @JsonProperty("token") String token) {
	}
}
