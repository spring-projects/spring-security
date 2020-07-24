/*
 * Copyright 2015-2018 the original author or authors.
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

import java.io.IOException;
import java.util.Set;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.MissingNode;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

/**
 * Custom Deserializer for {@link User} class. This is already registered with
 * {@link UserMixin}. You can also use it directly with your mixin class.
 *
 * @author Jitendra Singh
 * @since 4.2
 * @see UserMixin
 */
class UserDeserializer extends JsonDeserializer<User> {

	/**
	 * This method will create {@link User} object. It will ensure successful object
	 * creation even if password key is null in serialized json, because credentials may
	 * be removed from the {@link User} by invoking {@link User#eraseCredentials()}. In
	 * that case there won't be any password key in serialized json.
	 * @param jp the JsonParser
	 * @param ctxt the DeserializationContext
	 * @return the user
	 * @throws IOException if a exception during IO occurs
	 * @throws JsonProcessingException if an error during JSON processing occurs
	 */
	@Override
	public User deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException, JsonProcessingException {
		ObjectMapper mapper = (ObjectMapper) jp.getCodec();
		JsonNode jsonNode = mapper.readTree(jp);
		Set<? extends GrantedAuthority> authorities = mapper.convertValue(jsonNode.get("authorities"),
				new TypeReference<Set<SimpleGrantedAuthority>>() {
				});
		JsonNode password = readJsonNode(jsonNode, "password");
		User result = new User(readJsonNode(jsonNode, "username").asText(), password.asText(""),
				readJsonNode(jsonNode, "enabled").asBoolean(), readJsonNode(jsonNode, "accountNonExpired").asBoolean(),
				readJsonNode(jsonNode, "credentialsNonExpired").asBoolean(),
				readJsonNode(jsonNode, "accountNonLocked").asBoolean(), authorities);

		if (password.asText(null) == null) {
			result.eraseCredentials();
		}
		return result;
	}

	private JsonNode readJsonNode(JsonNode jsonNode, String field) {
		return jsonNode.has(field) ? jsonNode.get(field) : MissingNode.getInstance();
	}

}
