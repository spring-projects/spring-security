/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.test.context.support.oauth2.properties;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BinaryOperator;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Helps turn a
 * {@link org.springframework.security.test.context.support.oauth2.properties.Property @Property}
 * array into a {@link java.util.Map Map&lt;String, Object&gt;}
 *
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 *
 */
public class PropertyParsersHelper {
	/**
	 * <ul>
	 * <li>{@link org.springframework.security.test.context.support.oauth2.properties.NoOpPropertyParser
	 * NoOpPropertyParser} =&gt; keeps value as is.</li>
	 * <li>{@link org.springframework.security.test.context.support.oauth2.properties.BooleanPropertyParser
	 * BooleanPropertyParser} =&gt; Boolean</li>
	 * <li>{@link org.springframework.security.test.context.support.oauth2.properties.DoublePropertyParser
	 * DoublePropertyParser} =&gt; Double</li>
	 * <li>{@link org.springframework.security.test.context.support.oauth2.properties.InstantPropertyParser
	 * InstantPropertyParser} =&gt; {@link java.time.Instant Instant}</li>
	 * <li>{@link org.springframework.security.test.context.support.oauth2.properties.IntegerPropertyParser
	 * IntegerPropertyParser} =&gt; Integer</li>
	 * <li>{@link org.springframework.security.test.context.support.oauth2.properties.LongPropertyParser
	 * LongPropertyParser} =&gt; Long</li>
	 * <li>{@link org.springframework.security.test.context.support.oauth2.properties.StringListPropertyParser
	 * StringListPropertyParser} =&gt; List&lt;String&gt;</li>
	 * <li>{@link org.springframework.security.test.context.support.oauth2.properties.StringSetPropertyParser
	 * StringSetPropertyParser} =&gt; Set&lt;String&gt;</li>
	 * <li>{@link org.springframework.security.test.context.support.oauth2.properties.UrlPropertyParser
	 * UrlPropertyParser} =&gt; URL</li>
	 * </ul>
	 */
	public static final Set<String> DEFAULT_PARSERS = new HashSet<>();

	static {
		DEFAULT_PARSERS.add(
				"org.springframework.security.test.context.support.oauth2.properties.NoOpPropertyParser");
		DEFAULT_PARSERS.add(
				"org.springframework.security.test.context.support.oauth2.properties.BooleanPropertyParser");
		DEFAULT_PARSERS.add(
				"org.springframework.security.test.context.support.oauth2.properties.DoublePropertyParser");
		DEFAULT_PARSERS.add(
				"org.springframework.security.test.context.support.oauth2.properties.InstantPropertyParser");
		DEFAULT_PARSERS.add(
				"org.springframework.security.test.context.support.oauth2.properties.IntegerPropertyParser");
		DEFAULT_PARSERS.add(
				"org.springframework.security.test.context.support.oauth2.properties.LongPropertyParser");
		DEFAULT_PARSERS.add(
				"org.springframework.security.test.context.support.oauth2.properties.StringListPropertyParser");
		DEFAULT_PARSERS.add(
				"org.springframework.security.test.context.support.oauth2.properties.StringSetPropertyParser");
		DEFAULT_PARSERS.add(
				"org.springframework.security.test.context.support.oauth2.properties.UrlPropertyParser");
	}

	private final Map<String, PropertyParser<?>> parsers;

	private PropertyParsersHelper(final Set<String> parsers) {
		this.parsers = parsers.stream().map(t -> {
			try {
				return Class.forName(t);
			}
			catch (final ClassNotFoundException e) {
				throw new RuntimeException(e);
			}
		}).map(c -> {
			try {
				return (PropertyParser<?>) c.getDeclaredConstructor().newInstance();
			}
			catch (InstantiationException | IllegalAccessException
					| IllegalArgumentException | InvocationTargetException
					| NoSuchMethodException | SecurityException e) {
				throw new RuntimeException(
						"Missing public no-arg constructor on " + c.getName());
			}
		}).collect(Collectors.toMap(p -> p.getClass().getName(), p -> p));
	}

	/**
	 * @param parserClassName {@code Parser.class.getName()}
	 * @return Parser instance
	 */
	public PropertyParser<?> getParser(final String parserClassName) {
		return this.parsers.get(parserClassName);
	}

	private ParsedProperty<Object> parse(final Property p) {
		final PropertyParser<?> parser = getParser(p.parser());
		if (parser == null) {
			throw new RuntimeException(
					"No registered PropertyParser implementation for " + p.parser());
		}

		return new ParsedProperty<>(p.name(), parser.parse(p.value()));
	}

	/**
	 * <p>
	 * Turns a
	 * {@link org.springframework.security.test.context.support.oauth2.properties.Property @Property}
	 * array into a {@link java.util.Map Map&lt;String, Object&gt;} as required for
	 * {@link org.springframework.security.oauth2.jwt.Jwt JWT} headers and claims.
	 * </p>
	 * <p>
	 * Process highlights:
	 * </p>
	 * <ul>
	 * <li>each
	 * {@link org.springframework.security.test.context.support.oauth2.properties.Property#value()
	 * value()} is parsed according to
	 * {@link org.springframework.security.test.context.support.oauth2.properties.Property#parser()
	 * parser()}</li>
	 * <li>obtained values are associated with
	 * {@link org.springframework.security.test.context.support.oauth2.properties.Property#name()
	 * name()}</li>
	 * <li>values with same name are accumulated in the same collection</li>
	 * </ul>
	 *
	 * @param properties to be transformed
	 * @return processed properties
	 */
	@SuppressWarnings("unchecked")
	public Map<String, Object> parse(final Property... properties) {
		return Stream.of(properties).map(this::parse).collect(Collectors
				.toMap(ParsedProperty::getName, ParsedProperty::getValue, (v1, v2) -> {
					if (!(v1 instanceof Collection) || !(v2 instanceof Collection)) {
						throw new UnsupportedOperationException(
								"@Property values can be accumuleted only if instance of Collection");
					}
					if (v1 instanceof Map) {
						if (v2 instanceof Map) {
							return MAP_ACCUMULATOR.apply((Map<Object, Object>) v1,
									(Map<Object, Object>) v2);
						}
						throw new UnsupportedOperationException(
								"@Property \"Map\" values can only be accumulated with Maps");
					}
					if (v2 instanceof Map) {
						throw new UnsupportedOperationException(
								"@Property \"Map\" values can only be accumulated with Maps");
					}
					if (v1 instanceof List) {
						return LIST_ACCUMULATOR.apply((List<Object>) v1,
								(Collection<Object>) v2);
					}
					return SET_ACCUMULATOR.apply((Collection<Object>) v1,
							(Collection<Object>) v2);
				}));
	}

	private static Set<String> defaultParserNamesPlus(
			final String... additionalParserNames) {
		final Set<String> allParserNames = new HashSet<>(DEFAULT_PARSERS);
		allParserNames
				.addAll(Stream.of(additionalParserNames).collect(Collectors.toSet()));
		return allParserNames;
	}

	/**
	 * Instantiates default
	 * {@link org.springframework.security.test.context.support.oauth2.properties.PropertyParser
	 * PropertyParser}s plus all provided ones (using default constructor)
	 *
	 * @param additionalParserNames
	 * {@link org.springframework.security.test.context.support.oauth2.properties.PropertyParser
	 * PropertyParser} implementations class names to add to
	 * {@link org.springframework.security.test.context.support.oauth2.properties.PropertyParsersHelper#DEFAULT_PARSERS
	 * default ones}
	 * @return helper instance with provided parsers plus default ones
	 */
	public static PropertyParsersHelper withDefaultParsers(
			final String... additionalParserNames) {
		return new PropertyParsersHelper(defaultParserNamesPlus(additionalParserNames));
	}

	/**
	 * Instantiates all provided
	 * {@link org.springframework.security.test.context.support.oauth2.properties.PropertyParser
	 * PropertyParser}s using default constructor
	 *
	 * @param allParserNames
	 * {@link org.springframework.security.test.context.support.oauth2.properties.PropertyParser
	 * PropertyParser} implementations class names
	 * @return helper instance with provided parsers only
	 */
	public static PropertyParsersHelper withoutDefaultParsers(
			final String... allParserNames) {
		return new PropertyParsersHelper(
				Stream.of(allParserNames).collect(Collectors.toSet()));
	}

	private static final class ParsedProperty<T> {
		private final String name;
		private final T value;

		public ParsedProperty(final String name, final T value) {
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
