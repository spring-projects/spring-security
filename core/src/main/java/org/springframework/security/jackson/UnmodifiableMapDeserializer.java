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

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ValueDeserializer;

/**
 * Custom deserializer for {@link UnmodifiableMapMixin}.
 *
 * @author Ulrich Grave
 * @since 5.7
 * @see UnmodifiableMapMixin
 */
class UnmodifiableMapDeserializer extends ValueDeserializer<Map<?, ?>> {

	@Override
	public Map<?, ?> deserialize(JsonParser jp, DeserializationContext ctxt) throws JacksonException {
		JsonNode node = ctxt.readTree(jp);

		Map<String, Object> result = new LinkedHashMap<>();
		if (node != null && node.isObject()) {
			for (Map.Entry<String, JsonNode> field : node.properties()) {
				result.put(field.getKey(), ctxt.readTreeAsValue(field.getValue(), Object.class));
			}
		}
		return Collections.unmodifiableMap(result);
	}

}
