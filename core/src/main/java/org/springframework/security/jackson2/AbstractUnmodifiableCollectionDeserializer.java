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

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Set;

/**
 * Abstract base class for deserializers that create unmodifiable collections from JSON data.
 * Subclasses like {@link UnmodifiableListDeserializer} and
 * {@link UnmodifiableSetDeserializer} should implement the method to define the
 * specific collection type and handle the deserialization logic.
 *
 * @param <T> the type of the unmodifiable collection, such as {@link List} or {@link Set}.
 * @author Hyunmin Choi
 */
abstract class AbstractUnmodifiableCollectionDeserializer<T> extends JsonDeserializer<T> {

	@Override
	public T deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException {
		ObjectMapper mapper = (ObjectMapper) jp.getCodec();
		JsonNode node = mapper.readTree(jp);
		return createUnmodifiableCollection(node, mapper);
	}

	/**
	 * Creates an unmodifiable collection from the given JSON node.
	 *
	 * @param node the JSON node containing the data to be deserialized.
	 * @param mapper the {@link ObjectMapper} used to deserialize JSON data.
	 * @return an unmodifiable collection with the deserialized elements.
	 * @throws IOException if an error occurs during deserialization.
	 */
	protected abstract T createUnmodifiableCollection(JsonNode node, ObjectMapper mapper) throws IOException;

	/**
	 * Adds elements from the JSON node to the provided collection.
	 *
	 * @param node the JSON node containing the elements to add.
	 * @param mapper the {@link ObjectMapper} used for deserialization.
	 * @param collection the collection to which elements are added.
	 * @throws IOException if an error occurs during deserialization.
	 */
	protected void addElements(JsonNode node, ObjectMapper mapper, Collection<Object> collection) throws IOException {
		if (node instanceof ArrayNode arrayNode) {
			for (JsonNode elementNode : arrayNode) {
				collection.add(mapper.readValue(elementNode.traverse(mapper), Object.class));
			}
		} else if (node != null) {
			collection.add(mapper.readValue(node.traverse(mapper), Object.class));
		}
	}

}
