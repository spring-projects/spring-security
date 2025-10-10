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

import java.util.ArrayList;
import java.util.List;

import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonParser;
import tools.jackson.core.exc.StreamReadException;
import tools.jackson.databind.DatabindException;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JavaType;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ValueDeserializer;
import tools.jackson.databind.exc.InvalidTypeIdException;
import tools.jackson.databind.node.MissingNode;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

/**
 * Custom Deserializer for {@link User} class. This is already registered with
 * {@link UserMixin}. You can also use it directly with your mixin class.
 *
 * @author Sebastien Deleuze
 * @author Jitendra Singh
 * @since 7.0
 * @see UserMixin
 */
class UserDeserializer extends ValueDeserializer<User> {

	/**
	 * This method will create {@link User} object. It will ensure successful object
	 * creation even if password key is null in serialized json, because credentials may
	 * be removed from the {@link User} by invoking {@link User#eraseCredentials()}. In
	 * that case there won't be any password key in serialized json.
	 * @param jp the JsonParser
	 * @param ctxt the DeserializationContext
	 * @return the user
	 * @throws JacksonException if an error during JSON processing occurs
	 */
	@Override
	public User deserialize(JsonParser jp, DeserializationContext ctxt) throws JacksonException {
		JsonNode jsonNode = ctxt.readTree(jp);
		JsonNode authoritiesNode = readJsonNode(jsonNode, "authorities");
		List<GrantedAuthority> authorities = getAuthorities(jp, ctxt, authoritiesNode);
		JsonNode passwordNode = readJsonNode(jsonNode, "password");
		String username = readJsonNode(jsonNode, "username").asString();
		String password = (passwordNode.isMissingNode()) ? null : passwordNode.stringValue();
		boolean enabled = readJsonNode(jsonNode, "enabled").asBoolean();
		boolean accountNonExpired = readJsonNode(jsonNode, "accountNonExpired").asBoolean();
		boolean credentialsNonExpired = readJsonNode(jsonNode, "credentialsNonExpired").asBoolean();
		boolean accountNonLocked = readJsonNode(jsonNode, "accountNonLocked").asBoolean();
		User result = new User(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked,
				authorities);
		if (passwordNode.asString(null) == null) {
			result.eraseCredentials();
		}
		return result;
	}

	private List<GrantedAuthority> getAuthorities(JsonParser jp, DeserializationContext ctxt, JsonNode authoritiesNode)
			throws StreamReadException, DatabindException {
		List<GrantedAuthority> authorities = new ArrayList<>();
		if (!authoritiesNode.isNull() && authoritiesNode.isArray()) {
			for (JsonNode authorityNode : authoritiesNode.values()) {
				if (!authorityNode.has("@class")) {
					throw new InvalidTypeIdException(jp, "Missing '@class' property in an 'authorities' element",
							ctxt.constructType(GrantedAuthority.class), null);
				}
				JavaType type = ctxt.getTypeFactory().constructFromCanonical(authorityNode.get("@class").stringValue());
				if (type.isTypeOrSubTypeOf(GrantedAuthority.class)) {
					GrantedAuthority authority = ctxt.readTreeAsValue(authorityNode, type);
					authorities.add(authority);
				}
			}
		}
		return authorities;
	}

	private JsonNode readJsonNode(JsonNode jsonNode, String field) {
		return jsonNode.has(field) ? jsonNode.get(field) : MissingNode.getInstance();
	}

}
