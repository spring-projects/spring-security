/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.test.context.support.oauth2.attributes;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BinaryOperator;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Helps turn a {@link org.springframework.security.test.context.support.oauth2.attributes.Attribute @Attribute} array
 * into a {@link java.util.Map Map&lt;String, Object&gt;}
 *
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 *
 */
public class AttributeParsersHelper {
	/**
	 * <ul>
	 * <li>{@link NoOpStringParser} =&gt; keeps value as is.</li>
	 * <li>{@link BooleanStringParser} =&gt; Boolean</li>
	 * <li>{@link DoubleStringParser} =&gt; Double</li>
	 * <li>{@link InstantStringParser} =&gt; {@link java.time.Instant Instant}</li>
	 * <li>{@link IntegerStringParser} =&gt; Integer</li>
	 * <li>{@link LongStringParser} =&gt; Long</li>
	 * <li>{@link StringListStringParser} =&gt; List&lt;String&gt;</li>
	 * <li>{@link StringSetStringParser} =&gt; Set&lt;String&gt;</li>
	 * <li>{@link UrlStringParser} =&gt; URL</li>
	 * </ul>
	 */
	public static final Set<Parser<String, ?>> DEFAULT_PARSERS = new HashSet<>();

	static {
		DEFAULT_PARSERS.add(new NoOpStringParser());
		DEFAULT_PARSERS.add(new BooleanStringParser());
		DEFAULT_PARSERS.add(new DoubleStringParser());
		DEFAULT_PARSERS.add(new InstantStringParser());
		DEFAULT_PARSERS.add(new IntegerStringParser());
		DEFAULT_PARSERS.add(new LongStringParser());
		DEFAULT_PARSERS.add(new StringListStringParser());
		DEFAULT_PARSERS.add(new StringSetStringParser());
		DEFAULT_PARSERS.add(new UrlStringParser());
	}

	private final Map<String, Parser<String, ?>> parsers;

	@SuppressWarnings("unchecked")
	private AttributeParsersHelper(final Set<Parser<String, ?>> baseParsers, final String... additionalParserNames) {
		this.parsers = new HashMap<>(2 * DEFAULT_PARSERS.size() + 2 * additionalParserNames.length);
		final Stream<Parser<String, ?>> additionalParsers = Stream.of(additionalParserNames).distinct().map(t -> {
			try {
				return Class.forName(t);
			} catch (final ClassNotFoundException e) {
				throw new RuntimeException(e);
			}
		}).map(c -> {
			try {
				return (Parser<String, ?>) c.getDeclaredConstructor().newInstance();
			} catch (InstantiationException | IllegalAccessException | IllegalArgumentException
					| InvocationTargetException | NoSuchMethodException | SecurityException e) {
				throw new RuntimeException("Missing public no-arg constructor on " + c.getName());
			}
		});

		Stream.concat(baseParsers.stream(), additionalParsers).forEachOrdered(p -> {
			this.parsers.put(p.getClass().getName(), p);
			this.parsers.put(p.getClass().getSimpleName(), p);
		});
	}

	/**
	 * @param parserClassName {@code Parser.class.getName()}
	 * @return Parser instance
	 */
	public Parser<String, ?> getParser(final String parserClassName) {
		return this.parsers.get(parserClassName);
	}

	private ParsedProperty<Object> parse(final Attribute p) {
		final Parser<String, ?> parser = getParser(p.parser());
		if (parser == null) {
			throw new RuntimeException("No registered Parser implementation for " + p.parser());
		}

		return new ParsedProperty<>(p.name(), parser.parse(p.value()));
	}

	/**
	 * <p>
	 * Turns a {@link org.springframework.security.test.context.support.oauth2.attributes.Attribute @Attribute} array
	 * into a {@link java.util.Map Map&lt;String, Object&gt;} as required for
	 * {@link org.springframework.security.oauth2.jwt.Jwt JWT} headers and claims.
	 * </p>
	 * <p>
	 * Process highlights:
	 * </p>
	 * <ul>
	 * <li>each {@link org.springframework.security.test.context.support.oauth2.attributes.Attribute#value() value()} is
	 * parsed according to {@link org.springframework.security.test.context.support.oauth2.attributes.Attribute#parser()
	 * parser()}</li>
	 * <li>obtained values are associated with
	 * {@link org.springframework.security.test.context.support.oauth2.attributes.Attribute#name() name()}</li>
	 * <li>values with same name are accumulated in the same collection</li>
	 * </ul>
	 *
	 * @param properties to be transformed
	 * @return processed properties
	 */
	@SuppressWarnings("unchecked")
	public Map<String, Object> parse(final Attribute... properties) {
		return Stream.of(properties)
				.map(this::parse)
				.collect(Collectors.toMap(ParsedProperty::getName, ParsedProperty::getValue, (v1, v2) -> {
					if (!(v1 instanceof Collection) || !(v2 instanceof Collection)) {
						throw new UnsupportedOperationException(
								"@Attribute values can be accumuleted only if instance of Collection");
					}
					if (v1 instanceof Map) {
						if (v2 instanceof Map) {
							return MAP_ACCUMULATOR.apply((Map<Object, Object>) v1, (Map<Object, Object>) v2);
						}
						throw new UnsupportedOperationException(
								"@Attribute \"Map\" values can only be accumulated with Maps");
					}
					if (v2 instanceof Map) {
						throw new UnsupportedOperationException(
								"@Attribute \"Map\" values can only be accumulated with Maps");
					}
					if (v1 instanceof List) {
						return LIST_ACCUMULATOR.apply((List<Object>) v1, (Collection<Object>) v2);
					}
					return SET_ACCUMULATOR.apply((Collection<Object>) v1, (Collection<Object>) v2);
				}));
	}

	/**
	 * Instantiates default {@link org.springframework.security.test.context.support.oauth2.attributes.Parser Parser}s
	 * plus all provided ones (using default constructor)
	 *
	 * @param additionalParserNames {@link org.springframework.security.test.context.support.oauth2.attributes.Parser
	 * Parser} implementations class names to add to
	 * {@link org.springframework.security.test.context.support.oauth2.attributes.AttributeParsersHelper#DEFAULT_PARSERS
	 * default ones}
	 * @return helper instance with provided parsers plus default ones
	 */
	public static AttributeParsersHelper withDefaultParsers(final String... additionalParserNames) {
		return new AttributeParsersHelper(DEFAULT_PARSERS, additionalParserNames);
	}

	/**
	 * Instantiates all provided {@link org.springframework.security.test.context.support.oauth2.attributes.Parser
	 * Parser}s using default constructor
	 *
	 * @param allParserNames {@link org.springframework.security.test.context.support.oauth2.attributes.Parser Parser}
	 * implementations class names
	 * @return helper instance with provided parsers only
	 */
	public static AttributeParsersHelper withoutDefaultParsers(final String... allParserNames) {
		return new AttributeParsersHelper(Collections.emptySet(), allParserNames);
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
