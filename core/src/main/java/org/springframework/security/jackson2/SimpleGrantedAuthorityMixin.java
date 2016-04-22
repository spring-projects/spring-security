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

package org.springframework.security.jackson2;

import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * Jackson Mixin class helps in serialize/deserialize
 * {@link org.springframework.security.core.authority.SimpleGrantedAuthority}.
 *
 * <pre>
 *     ObjectMapper mapper = new ObjectMapper();
 *     mapper.addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityMixin.class);
 * </pre>
 * @author Jitendra Singh
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY)
@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class SimpleGrantedAuthorityMixin {

	/**
	 * Mixin Constructor.
	 * @param role
	 */
	@JsonCreator
	public SimpleGrantedAuthorityMixin(@JsonProperty("role") String role) {
	}

	/**
	 * This method will ensure that getAuthority() doesn't serialized to <b>authority</b> key, it will be serialized
	 * as <b>role</b> key. Because above mixin constructor will look for role key to properly deserialize.
	 *
	 * @return
	 */
	@JsonProperty("role")
	public abstract String getAuthority();
}
