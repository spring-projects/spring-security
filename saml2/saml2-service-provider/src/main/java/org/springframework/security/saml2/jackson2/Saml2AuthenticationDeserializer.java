/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.saml2.jackson2;

import java.io.IOException;
import java.util.List;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;

/**
 * Custom deserializer for {@link Saml2Authentication}.
 *
 * @author Ulrich Grave
 * @since 5.7
 * @see Saml2AuthenticationMixin
 */
class Saml2AuthenticationDeserializer extends JsonDeserializer<Saml2Authentication> {

	private static final TypeReference<List<GrantedAuthority>> GRANTED_AUTHORITY_LIST = new TypeReference<List<GrantedAuthority>>() {
	};

	private static final TypeReference<Object> OBJECT = new TypeReference<Object>() {
	};

	@Override
	public Saml2Authentication deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException {
		ObjectMapper mapper = (ObjectMapper) jp.getCodec();
		JsonNode jsonNode = mapper.readTree(jp);

		boolean authenticated = JsonNodeUtils.readJsonNode(jsonNode, "authenticated").asBoolean();
		JsonNode principalNode = JsonNodeUtils.readJsonNode(jsonNode, "principal");
		AuthenticatedPrincipal principal = getPrincipal(mapper, principalNode);
		String saml2Response = JsonNodeUtils.findStringValue(jsonNode, "saml2Response");
		List<GrantedAuthority> authorities = JsonNodeUtils.findValue(jsonNode, "authorities", GRANTED_AUTHORITY_LIST,
				mapper);
		Object details = JsonNodeUtils.findValue(jsonNode, "details", OBJECT, mapper);

		Saml2Authentication authentication = new Saml2Authentication(principal, saml2Response, authorities);
		authentication.setAuthenticated(authenticated);
		authentication.setDetails(details);
		return authentication;
	}

	private AuthenticatedPrincipal getPrincipal(ObjectMapper mapper, JsonNode principalNode) throws IOException {
		return mapper.readValue(principalNode.traverse(mapper), AuthenticatedPrincipal.class);
	}

}
