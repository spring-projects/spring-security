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

import java.util.Collection;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

import org.springframework.security.core.GrantedAuthority;

/**
 * This is a Jackson mixin class helps in serialize/deserialize
 * {@link org.springframework.security.authentication.AnonymousAuthenticationToken} class.
 *
 * @author Sebastien Deleuze
 * @author Jitendra Singh
 * @since 7.0
 * @see CoreJacksonModule
 * @see SecurityJacksonModules
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, isGetterVisibility = JsonAutoDetect.Visibility.NONE,
		getterVisibility = JsonAutoDetect.Visibility.NONE, creatorVisibility = JsonAutoDetect.Visibility.ANY)
class TestingAuthenticationTokenMixin {

	/**
	 * Constructor used by Jackson to create object of
	 * {@link org.springframework.security.authentication.AnonymousAuthenticationToken}.
	 * {@link org.springframework.security.authentication.AnonymousAuthenticationToken#AnonymousAuthenticationToken(String, Object, Collection)}
	 * @param principal the principal (typically a <code>UserDetails</code>)
	 * @param credentials the credentials
	 * @param authorities the authorities granted to the principal
	 */
	@JsonCreator
	TestingAuthenticationTokenMixin(@JsonProperty("principal") Object principal,
			@JsonProperty("credentials") Object credentials,
			@JsonProperty("authorities") Collection<? extends GrantedAuthority> authorities) {
	}

}
