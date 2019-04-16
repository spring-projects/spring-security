/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.test.context.support;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.function.BinaryOperator;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.security.oauth2.core.OAuth2AccessToken;

/**
 * Helps turn a
 * {@link org.springframework.security.test.context.support.StringAttribute @StringAttribute} array
 * into a {@link java.util.Map Map&lt;String, Object&gt;}
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 * @since 5.2
 *
 */
class StringAttributeParserSupport {
	private final Map<Class<? extends AttributeValueParser<String, ?>>, AttributeValueParser<String, ?>> parsers = new HashMap<>();

	private AttributeValueParser<String, ?> getParser(final Class<? extends AttributeValueParser<String, ?>> parserClass) {
		if (!parsers.containsKey(parserClass)) {
			register(parserClass);
		}
		return parsers.get(parserClass);
	}

	private AttributeValueParser<String, ?> register(final Class<? extends AttributeValueParser<String, ?>> parserClass) {
		try {
			final AttributeValueParser<String, ?> parser = parserClass.getDeclaredConstructor().newInstance();
			this.parsers.put(parserClass, parser);
			return parser;
		} catch (final Exception e) {
			throw new RuntimeException("Missing public no-arg constructor on " + parserClass.getName());
		}
	}

	private ParsedAttribute<?> parse(final StringAttribute stringAttribute) {
		return new ParsedAttribute<>(stringAttribute.name(), getParser(stringAttribute.parser()).parse(stringAttribute.value()));
	}

	/**
	 * <p>
	 * Turns a {@link StringAttribute @StringAttribute} array into a {@link Map Map&lt;String,
	 * Object&gt;} as required for instance by
	 * {@link org.springframework.security.oauth2.jwt.Jwt JWT} headers and claims or
	 * {@link OAuth2AccessToken} attributes.
	 * </p>
	 * <p>
	 * Process highlights:
	 * </p>
	 * <ul>
	 * <li>each {@link StringAttribute#value() value()} is parsed using
	 * {@link StringAttribute#parser()}</li>
	 * <li>obtained values are associated with {@link StringAttribute#name()}</li>
	 * <li>values with same name are accumulated in the same collection</li>
	 * </ul>
	 *
	 * @param properties to be transformed
	 * @return processed properties
	 */
	@SuppressWarnings("unchecked")
	public Map<String, Object> parse(final StringAttribute... properties) {
		return Stream.of(properties)
				.map(this::parse)
				.collect(Collectors.toMap(ParsedAttribute::getName, ParsedAttribute::getValue, (v1, v2) -> {
					if (!(v1 instanceof Collection) || !(v2 instanceof Collection)) {
						throw new UnsupportedOperationException(
								"@StringAttribute values can be accumuleted only if instance of Collection");
					}
					if (v1 instanceof Map) {
						if (v2 instanceof Map) {
							return MAP_ACCUMULATOR.apply((Map<Object, Object>) v1, (Map<Object, Object>) v2);
						}
						throw new UnsupportedOperationException(
								"@StringAttribute \"Map\" values can only be accumulated with Maps");
					}
					if (v2 instanceof Map) {
						throw new UnsupportedOperationException(
								"@StringAttribute \"Map\" values can only be accumulated with Maps");
					}
					if (v1 instanceof List) {
						return LIST_ACCUMULATOR.apply((List<Object>) v1, (Collection<Object>) v2);
					}
					return SET_ACCUMULATOR.apply((Collection<Object>) v1, (Collection<Object>) v2);
				}));
	}

	private static final class ParsedAttribute<T> {
		private final String name;
		private final T value;

		public ParsedAttribute(final String name, final T value) {
			super();
			this.name = name;
			this.value = value;
		}

		public String getName() {
			return name;
		}

		public T getValue() {
			return value;
		}

	}

	private static BinaryOperator<Collection<Object>> SET_ACCUMULATOR = (v1, v2) -> {
		final HashSet<Object> all = new HashSet<>(v1.size() + v2.size());
		all.addAll(v1);
		all.addAll(v2);
		return all;
	};

	private static BinaryOperator<Collection<Object>> LIST_ACCUMULATOR = (v1, v2) -> {
		final ArrayList<Object> all = new ArrayList<>(v1.size() + v2.size());
		all.addAll(v1);
		all.addAll(v2);
		return all;
	};

	private static BinaryOperator<Map<Object, Object>> MAP_ACCUMULATOR = (v1, v2) -> {
		final HashMap<Object, Object> all = new HashMap<>(v1.size() + v2.size());
		all.putAll(v1);
		all.putAll(v2);
		return all;
	};
}
