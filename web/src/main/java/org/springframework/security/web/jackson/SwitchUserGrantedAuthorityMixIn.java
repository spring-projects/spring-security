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

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.switchuser.SwitchUserGrantedAuthority;

/**
 * Jackson mixin class to serialize/deserialize {@link SwitchUserGrantedAuthority}.
 *
 * @author Sebastien Deleuze
 * @author Markus Heiden
 * @since 7.0
 * @see WebJacksonModule
 * @see WebServletJacksonModule
 * @see org.springframework.security.jackson.SecurityJacksonModules
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, getterVisibility = JsonAutoDetect.Visibility.NONE,
		isGetterVisibility = JsonAutoDetect.Visibility.NONE)
abstract class SwitchUserGrantedAuthorityMixIn {

	@JsonCreator
	SwitchUserGrantedAuthorityMixIn(@JsonProperty("role") String role, @JsonProperty("source") Authentication source) {
	}

}
