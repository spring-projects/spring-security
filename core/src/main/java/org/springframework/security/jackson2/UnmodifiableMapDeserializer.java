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

package org.springframework.security.jackson2;

import java.io.IOException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Custom deserializer for {@link UnmodifiableMapMixin}.
 *
 * @author Ulrich Grave
 * @since 5.7
 * @see UnmodifiableMapMixin
 */
class UnmodifiableMapDeserializer extends JsonDeserializer<Map<?, ?>> {

	@Override
	public Map<?, ?> deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException {
		ObjectMapper mapper = (ObjectMapper) jp.getCodec();
		JsonNode node = mapper.readTree(jp);

		Map<String, Object> result = new LinkedHashMap<>();
		if (node != null && node.isObject()) {
			Iterable<Map.Entry<String, JsonNode>> fields = node::fields;
			for (Map.Entry<String, JsonNode> field : fields) {
				result.put(field.getKey(), mapper.readValue(field.getValue().traverse(mapper), Object.class));
			}
		}
		return Collections.unmodifiableMap(result);
	}

}
