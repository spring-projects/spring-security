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

import java.util.List;

import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonParser;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ValueDeserializer;
import tools.jackson.databind.node.MissingNode;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

/**
 * Custom deserializer for {@link PreAuthenticatedAuthenticationToken}. At the time of
 * deserialization it will invoke suitable constructor depending on the value of
 * <b>authenticated</b> property. It will ensure that the token's state must not change.
 *
 * @author Sebastien Deleuze
 * @author Jitendra Singh
 * @since 7.0
 * @see PreAuthenticatedAuthenticationTokenMixin
 */
class PreAuthenticatedAuthenticationTokenDeserializer extends ValueDeserializer<PreAuthenticatedAuthenticationToken> {

	private static final TypeReference<List<GrantedAuthority>> GRANTED_AUTHORITY_LIST = new TypeReference<>() {
	};

	/**
	 * This method construct {@link PreAuthenticatedAuthenticationToken} object from
	 * serialized json.
	 * @param jp the JsonParser
	 * @param ctxt the DeserializationContext
	 * @return the user
	 * @throws tools.jackson.core.JacksonException if an error during JSON processing
	 * occurs
	 */
	@Override
	public PreAuthenticatedAuthenticationToken deserialize(JsonParser jp, DeserializationContext ctxt)
			throws JacksonException {
		JsonNode jsonNode = ctxt.readTree(jp);
		boolean authenticated = readJsonNode(jsonNode, "authenticated").asBoolean();
		JsonNode principalNode = readJsonNode(jsonNode, "principal");
		Object principal = (!principalNode.isObject()) ? principalNode.stringValue()
				: ctxt.readTreeAsValue(principalNode, Object.class);
		Object credentials = readJsonNode(jsonNode, "credentials").stringValue();
		JsonNode authoritiesNode = readJsonNode(jsonNode, "authorities");
		List<GrantedAuthority> authorities = ctxt.readTreeAsValue(authoritiesNode,
				ctxt.getTypeFactory().constructType(GRANTED_AUTHORITY_LIST));
		PreAuthenticatedAuthenticationToken token = (!authenticated)
				? new PreAuthenticatedAuthenticationToken(principal, credentials)
				: new PreAuthenticatedAuthenticationToken(principal, credentials, authorities);
		token.setDetails(readJsonNode(jsonNode, "details"));
		return token;
	}

	private JsonNode readJsonNode(JsonNode jsonNode, String field) {
		return jsonNode.has(field) ? jsonNode.get(field) : MissingNode.getInstance();
	}

}
