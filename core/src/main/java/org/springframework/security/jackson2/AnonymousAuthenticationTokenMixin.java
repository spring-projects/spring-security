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

package org.springframework.security.jackson2;

import java.util.Collection;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

import org.springframework.security.core.GrantedAuthority;

/**
 * This is a Jackson mixin class helps in serialize/deserialize
 * {@link org.springframework.security.authentication.AnonymousAuthenticationToken} class.
 * To use this class you need to register it with
 * {@link com.fasterxml.jackson.databind.ObjectMapper} and
 * {@link SimpleGrantedAuthorityMixin} because AnonymousAuthenticationToken contains
 * SimpleGrantedAuthority. <pre>
 *     ObjectMapper mapper = new ObjectMapper();
 *     mapper.registerModule(new CoreJackson2Module());
 * </pre>
 *
 * <i>Note: This class will save full class name into a property called @class</i>
 *
 * @author Jitendra Singh
 * @since 4.2
 * @see CoreJackson2Module
 * @see SecurityJackson2Modules
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, isGetterVisibility = JsonAutoDetect.Visibility.NONE,
		getterVisibility = JsonAutoDetect.Visibility.NONE, creatorVisibility = JsonAutoDetect.Visibility.ANY)
@JsonIgnoreProperties(ignoreUnknown = true)
class AnonymousAuthenticationTokenMixin {

	/**
	 * Constructor used by Jackson to create object of
	 * {@link org.springframework.security.authentication.AnonymousAuthenticationToken}.
	 * @param keyHash hashCode of key provided at the time of token creation by using
	 * {@link org.springframework.security.authentication.AnonymousAuthenticationToken#AnonymousAuthenticationToken(String, Object, Collection)}
	 * @param principal the principal (typically a <code>UserDetails</code>)
	 * @param authorities the authorities granted to the principal
	 */
	@JsonCreator
	AnonymousAuthenticationTokenMixin(@JsonProperty("keyHash") Integer keyHash,
			@JsonProperty("principal") Object principal,
			@JsonProperty("authorities") Collection<? extends GrantedAuthority> authorities) {
	}

}
