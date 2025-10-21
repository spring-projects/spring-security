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

package org.springframework.security.web.jackson2;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

/**
 * Jackson mixin class to serialize/deserialize
 * {@link org.springframework.security.web.authentication.WebAuthenticationDetails}.
 *
 * <pre>
 * 	ObjectMapper mapper = new ObjectMapper();
 *	mapper.registerModule(new WebServletJackson2Module());
 * </pre>
 *
 * @author Jitendra Singh
 * @since 4.2
 * @see WebServletJackson2Module
 * @see org.springframework.security.jackson2.SecurityJackson2Modules
 * @deprecated as of 7.0 in favor of
 * {@code org.springframework.security.web.jackson.SwitchUserGrantedAuthorityMixIn} based
 * on Jackson 3
 */
@SuppressWarnings("removal")
@Deprecated(forRemoval = true)
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY)
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, getterVisibility = JsonAutoDetect.Visibility.NONE,
		isGetterVisibility = JsonAutoDetect.Visibility.NONE, creatorVisibility = JsonAutoDetect.Visibility.ANY)
class WebAuthenticationDetailsMixin {

	@JsonCreator
	WebAuthenticationDetailsMixin(@JsonProperty("remoteAddress") String remoteAddress,
			@JsonProperty("sessionId") String sessionId) {
	}

}
