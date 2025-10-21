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

package org.springframework.security.jackson2;

import java.util.Collection;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

import org.springframework.security.core.GrantedAuthority;

/**
 * This mixin class helps in serialize/deserialize
 * {@link org.springframework.security.authentication.RememberMeAuthenticationToken}
 * class. To use this class you need to register it with
 * {@link com.fasterxml.jackson.databind.ObjectMapper} and 2 more mixin classes.
 *
 * <ol>
 * <li>{@link SimpleGrantedAuthorityMixin}</li>
 * <li>{@link UserMixin}</li>
 * <li>{@link UnmodifiableSetMixin}</li>
 * </ol>
 *
 * <pre>
 *     ObjectMapper mapper = new ObjectMapper();
 *     mapper.registerModule(new CoreJackson2Module());
 * </pre>
 *
 * <i>Note: This class will save TypeInfo (full class name) into a property
 * called @class</i>
 *
 * @author Jitendra Singh
 * @since 4.2
 * @see CoreJackson2Module
 * @see SecurityJackson2Modules
 * @deprecated as of 7.0 in favor of
 * {@code org.springframework.security.jackson.RememberMeAuthenticationTokenMixin} based
 * on Jackson 3
 */
@SuppressWarnings("removal")
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, getterVisibility = JsonAutoDetect.Visibility.NONE,
		isGetterVisibility = JsonAutoDetect.Visibility.NONE, creatorVisibility = JsonAutoDetect.Visibility.ANY)
@JsonIgnoreProperties(ignoreUnknown = true)
@Deprecated(forRemoval = true)
class RememberMeAuthenticationTokenMixin {

	/**
	 * Constructor used by Jackson to create
	 * {@link org.springframework.security.authentication.RememberMeAuthenticationToken}
	 * object.
	 * @param keyHash hashCode of above given key.
	 * @param principal the principal (typically a <code>UserDetails</code>)
	 * @param authorities the authorities granted to the principal
	 */
	@JsonCreator
	RememberMeAuthenticationTokenMixin(@JsonProperty("keyHash") Integer keyHash,
			@JsonProperty("principal") Object principal,
			@JsonProperty("authorities") Collection<? extends GrantedAuthority> authorities) {
	}

}
