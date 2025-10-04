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

import org.jspecify.annotations.Nullable;
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
 * @author Sebastien Deleuze
 * @author Jitendra Singh
 * @author Greg Turnquist
 * @author Onur Kagan Ozcan
 * @since 7.0
 * @see UsernamePasswordAuthenticationTokenMixin
 */
class UsernamePasswordAuthenticationTokenDeserializer extends ValueDeserializer<UsernamePasswordAuthenticationToken> {

	/**
	 * This method construct {@link UsernamePasswordAuthenticationToken} object from
	 * serialized json.
	 * @param jp the JsonParser
	 * @param ctxt the DeserializationContext
	 * @return the user
	 * @throws JacksonException if an error during JSON processing occurs
	 */
	@Override
	public UsernamePasswordAuthenticationToken deserialize(JsonParser jp, DeserializationContext ctxt)
			throws JacksonException {
		JsonNode jsonNode = ctxt.readTree(jp);
		boolean authenticated = readJsonNode(jsonNode, "authenticated").asBoolean();
		JsonNode principalNode = readJsonNode(jsonNode, "principal");
		Object principal = getPrincipal(ctxt, principalNode);
		JsonNode credentialsNode = readJsonNode(jsonNode, "credentials");
		Object credentials = getCredentials(credentialsNode);
		JsonNode authoritiesNode = readJsonNode(jsonNode, "authorities");
		List<GrantedAuthority> authorities = getAuthorities(jp, ctxt, authoritiesNode);
		UsernamePasswordAuthenticationToken token = (!authenticated)
				? UsernamePasswordAuthenticationToken.unauthenticated(principal, credentials)
				: UsernamePasswordAuthenticationToken.authenticated(principal, credentials, authorities);
		JsonNode detailsNode = readJsonNode(jsonNode, "details");
		if (detailsNode.isNull() || detailsNode.isMissingNode()) {
			token.setDetails(null);
		}
		else {
			Object details = ctxt.readTreeAsValue(detailsNode, Object.class);
			token.setDetails(details);
		}
		return token;
	}

	private @Nullable Object getCredentials(JsonNode credentialsNode) {
		if (credentialsNode.isNull() || credentialsNode.isMissingNode()) {
			return null;
		}
		return credentialsNode.asString();
	}

	private Object getPrincipal(DeserializationContext ctxt, JsonNode principalNode)
			throws StreamReadException, DatabindException {
		if (principalNode.isObject()) {
			JavaType type = ctxt.getTypeFactory().constructFromCanonical(principalNode.get("@class").stringValue());
			return ctxt.readTreeAsValue(principalNode, type);
		}
		return principalNode.asString();
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
