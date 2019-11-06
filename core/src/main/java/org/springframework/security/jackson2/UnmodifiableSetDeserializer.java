/*
 * Copyright 2015-2016 the original author or authors.
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

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;

import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Custom deserializer for {@link UnmodifiableSetMixin}.
 *
 * @author Jitendra Singh
 * @see UnmodifiableSetMixin
 * @since 4.2
 */
class UnmodifiableSetDeserializer extends JsonDeserializer<Set> {

	@Override
	public Set deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException, JsonProcessingException {
		ObjectMapper mapper = (ObjectMapper) jp.getCodec();
		JsonNode node = mapper.readTree(jp);
		Set<Object> resultSet = new HashSet<>();
		if (node != null) {
			if (node instanceof ArrayNode) {
				ArrayNode arrayNode = (ArrayNode) node;
				for (JsonNode elementNode : arrayNode) {
					resultSet.add(mapper.readValue(elementNode.traverse(mapper), Object.class));
				}
			} else {
				resultSet.add(mapper.readValue(node.traverse(mapper), Object.class));
			}
		}
		return Collections.unmodifiableSet(resultSet);
	}
}
