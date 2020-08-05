/*
 * Copyright 2015-2016 the original author or authors.
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

package org.springframework.security.web.jackson2;

import com.fasterxml.jackson.annotation.*;

/**
 * Jackson mixin class to serialize/deserialize
 * {@link org.springframework.security.web.savedrequest.SavedCookie} serialization
 * support.
 *
 * <pre>
 * 		ObjectMapper mapper = new ObjectMapper();
 *		mapper.registerModule(new WebServletJackson2Module());
 * </pre>
 *
 * @author Jitendra Singh.
 * @see WebServletJackson2Module
 * @see org.springframework.security.jackson2.SecurityJackson2Modules
 * @since 4.2
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, getterVisibility = JsonAutoDetect.Visibility.NONE)
@JsonIgnoreProperties(ignoreUnknown = true)
abstract class SavedCookieMixin {

	@JsonCreator
	SavedCookieMixin(@JsonProperty("name") String name, @JsonProperty("value") String value,
			@JsonProperty("comment") String comment, @JsonProperty("domain") String domain,
			@JsonProperty("maxAge") int maxAge, @JsonProperty("path") String path,
			@JsonProperty("secure") boolean secure, @JsonProperty("version") int version) {

	}

}
