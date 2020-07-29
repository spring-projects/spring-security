/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.oauth2.client.jackson2;

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
 * A {@code JsonDeserializer} for {@link Collections#unmodifiableMap(Map)}.
 *
 * @author Joe Grandja
 * @since 5.3
 * @see Collections#unmodifiableMap(Map)
 * @see UnmodifiableMapMixin
 */
final class UnmodifiableMapDeserializer extends JsonDeserializer<Map<?, ?>> {

	@Override
	public Map<?, ?> deserialize(JsonParser parser, DeserializationContext context) throws IOException {
		ObjectMapper mapper = (ObjectMapper) parser.getCodec();
		JsonNode mapNode = mapper.readTree(parser);
		Map<String, Object> result = new LinkedHashMap<>();
		if (mapNode != null && mapNode.isObject()) {
			Iterable<Map.Entry<String, JsonNode>> fields = mapNode::fields;
			for (Map.Entry<String, JsonNode> field : fields) {
				result.put(field.getKey(), mapper.readValue(field.getValue().traverse(mapper), Object.class));
			}
		}
		return Collections.unmodifiableMap(result);
	}

}
