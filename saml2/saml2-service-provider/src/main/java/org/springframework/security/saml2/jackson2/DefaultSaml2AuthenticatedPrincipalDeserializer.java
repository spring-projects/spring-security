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
import java.util.Map;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;

/**
 * Custom deserializer for {@link DefaultSaml2AuthenticatedPrincipal}.
 *
 * @author Ulrich Grave
 * @since 5.7
 * @see DefaultSaml2AuthenticatedPrincipalMixin
 */
class DefaultSaml2AuthenticatedPrincipalDeserializer extends JsonDeserializer<DefaultSaml2AuthenticatedPrincipal> {

	private static final TypeReference<List<String>> SESSION_INDICES_LIST = new TypeReference<List<String>>() {
	};

	private static final TypeReference<Map<String, List<Object>>> ATTRIBUTES_MAP = new TypeReference<Map<String, List<Object>>>() {
	};

	@Override
	public DefaultSaml2AuthenticatedPrincipal deserialize(JsonParser jp, DeserializationContext ctxt)
			throws IOException {
		ObjectMapper mapper = (ObjectMapper) jp.getCodec();
		JsonNode jsonNode = mapper.readTree(jp);

		String name = JsonNodeUtils.findStringValue(jsonNode, "name");
		Map<String, List<Object>> attributes = JsonNodeUtils.findValue(jsonNode, "attributes", ATTRIBUTES_MAP, mapper);
		List<String> sessionIndexes = JsonNodeUtils.findValue(jsonNode, "sessionIndexes", SESSION_INDICES_LIST, mapper);
		String registrationId = JsonNodeUtils.findStringValue(jsonNode, "registrationId");

		DefaultSaml2AuthenticatedPrincipal principal = new DefaultSaml2AuthenticatedPrincipal(name, attributes,
				sessionIndexes);
		if (registrationId != null) {
			principal.setRelyingPartyRegistrationId(registrationId);
		}
		return principal;
	}

}
