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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.MissingNode;

final class JsonNodeUtils {

	private JsonNodeUtils() {
	}

	static String findStringValue(JsonNode jsonNode, String fieldName) {
		if (jsonNode == null) {
			return null;
		}
		JsonNode value = jsonNode.findValue(fieldName);
		return (value != null && value.isTextual()) ? value.asText() : null;
	}

	static <T> T findValue(JsonNode jsonNode, String fieldName, TypeReference<T> valueTypeReference,
			ObjectMapper mapper) {
		if (jsonNode == null) {
			return null;
		}
		JsonNode value = jsonNode.findValue(fieldName);
		return (value != null && value.isContainerNode()) ? mapper.convertValue(value, valueTypeReference) : null;
	}

	static JsonNode readJsonNode(JsonNode jsonNode, String field) {
		return jsonNode.has(field) ? jsonNode.get(field) : MissingNode.getInstance();
	}

}
