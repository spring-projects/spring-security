/*
 * Copyright 2024 the original author or authors.
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
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;

/**
 * Abstract base class for deserializers that create unmodifiable collections from JSON
 * data. Subclasses like {@link UnmodifiableListDeserializer} and
 * {@link UnmodifiableSetDeserializer} should implement the method to define the specific
 * collection type and handle the deserialization logic.
 *
 * @param <T> the type of the unmodifiable collection, such as {@link List} or
 * {@link Set}.
 * @author Hyunmin Choi
 */
abstract class AbstractUnmodifiableCollectionDeserializer<T> extends JsonDeserializer<T> {

	@Override
	public T deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException {
		ObjectMapper mapper = (ObjectMapper) jp.getCodec();
		JsonNode node = mapper.readTree(jp);
		Collection<Object> values = new ArrayList<>();
		if (node instanceof ArrayNode arrayNode) {
			for (JsonNode elementNode : arrayNode) {
				values.add(mapper.readValue(elementNode.traverse(mapper), Object.class));
			}
		}
		else if (node != null) {
			values.add(mapper.readValue(node.traverse(mapper), Object.class));
		}
		return createUnmodifiableCollection(values);
	}

	/**
	 * Creates an unmodifiable collection from the given JSON node.
	 * @param values the values to add to the unmodifiable collection
	 * @return an unmodifiable collection with the deserialized elements.
	 * @throws IOException if an error occurs during deserialization.
	 */
	abstract T createUnmodifiableCollection(Collection<Object> values) throws IOException;

}
