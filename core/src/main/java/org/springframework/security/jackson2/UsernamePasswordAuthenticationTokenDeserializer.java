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
import java.util.List;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.MissingNode;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

/**
 * Custom deserializer for {@link UsernamePasswordAuthenticationToken}. At the time of
 * deserialization it will invoke suitable constructor depending on the value of
 * <b>authenticated</b> property. It will ensure that the token's state must not change.
 * <p>
 * This deserializer is already registered with
 * {@link UsernamePasswordAuthenticationTokenMixin} but you can also registered it with
 * your own mixin class.
 *
 * @author Jitendra Singh
 * @author Greg Turnquist
 * @author Onur Kagan Ozcan
 * @since 4.2
 * @see UsernamePasswordAuthenticationTokenMixin
 */
class UsernamePasswordAuthenticationTokenDeserializer extends JsonDeserializer<UsernamePasswordAuthenticationToken> {

	/**
	 * This method construct {@link UsernamePasswordAuthenticationToken} object from
	 * serialized json.
	 * @param jp the JsonParser
	 * @param ctxt the DeserializationContext
	 * @return the user
	 * @throws IOException if a exception during IO occurs
	 * @throws JsonProcessingException if an error during JSON processing occurs
	 */
	@Override
	public UsernamePasswordAuthenticationToken deserialize(JsonParser jp, DeserializationContext ctxt)
			throws IOException, JsonProcessingException {
		UsernamePasswordAuthenticationToken token = null;
		ObjectMapper mapper = (ObjectMapper) jp.getCodec();
		JsonNode jsonNode = mapper.readTree(jp);
		Boolean authenticated = readJsonNode(jsonNode, "authenticated").asBoolean();
		JsonNode principalNode = readJsonNode(jsonNode, "principal");
		Object principal = null;
		if (principalNode.isObject()) {
			principal = mapper.readValue(principalNode.traverse(mapper), Object.class);
		}
		else {
			principal = principalNode.asText();
		}
		JsonNode credentialsNode = readJsonNode(jsonNode, "credentials");
		Object credentials;
		if (credentialsNode.isNull() || credentialsNode.isMissingNode()) {
			credentials = null;
		}
		else {
			credentials = credentialsNode.asText();
		}
		List<GrantedAuthority> authorities = mapper.readValue(readJsonNode(jsonNode, "authorities").traverse(mapper),
				new TypeReference<List<GrantedAuthority>>() {
				});
		if (authenticated) {
			token = new UsernamePasswordAuthenticationToken(principal, credentials, authorities);
		}
		else {
			token = new UsernamePasswordAuthenticationToken(principal, credentials);
		}
		JsonNode detailsNode = readJsonNode(jsonNode, "details");
		if (detailsNode.isNull() || detailsNode.isMissingNode()) {
			token.setDetails(null);
		}
		else {
			Object details = mapper.readValue(detailsNode.toString(), new TypeReference<Object>() {
			});
			token.setDetails(details);
		}
		return token;
	}

	private JsonNode readJsonNode(JsonNode jsonNode, String field) {
		return jsonNode.has(field) ? jsonNode.get(field) : MissingNode.getInstance();
	}

}
