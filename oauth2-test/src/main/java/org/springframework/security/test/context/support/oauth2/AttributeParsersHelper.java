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
package org.springframework.security.test.context.support.oauth2;

import java.lang.reflect.InvocationTargetException;
import java.net.MalformedURLException;
import java.net.URL;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.BinaryOperator;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.util.StringUtils;

/**
 * Helps turn a {@link org.springframework.security.test.context.support.oauth2.Attribute @Attribute} array into a
 * {@link java.util.Map Map&lt;String, Object&gt;}
 *
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 *
 */
class AttributeParsersHelper {
	public enum TargetType {
		STRING, BOOLEAN, DOUBLE, INSTANT, INTEGER, LONG, STRING_LIST, STRING_SET, URL, OTHER;
	}

	private final Map<String, AttributeValueParser<?>> parsers;

	private AttributeParsersHelper(
			final Map<String, AttributeValueParser<?>> baseParsers,
			final String... additionalParserNames) {
		this.parsers = new HashMap<>(baseParsers);

		Stream.of(additionalParserNames).distinct().map(t -> {
			try {
				return Class.forName(t);
			} catch (final ClassNotFoundException e) {
				throw new RuntimeException(e);
			}
		}).map(c -> {
			try {
				return (AttributeValueParser<?>) c.getDeclaredConstructor().newInstance();
			} catch (InstantiationException | IllegalAccessException | IllegalArgumentException
					| InvocationTargetException | NoSuchMethodException | SecurityException e) {
				throw new RuntimeException("Missing public no-arg constructor on " + c.getName());
			}
		}).forEachOrdered(p -> {
			this.parsers.put(p.getClass().getName(), p);
			this.parsers.put(p.getClass().getSimpleName(), p);
		});
	}

	private AttributeValueParser<?> getParser(final TargetType targetType, final String parserOverrideClassName) {
		final Optional<AttributeValueParser<?>> parserOverride =
				Optional.ofNullable(StringUtils.isEmpty(parserOverrideClassName) ? null : parserOverrideClassName)
						.map(parsers::get);

		switch (targetType) {
		case STRING:
			return parserOverride.orElse(parsers.get("NoOpParser"));
		case BOOLEAN:
			return parserOverride.orElse(parsers.get("BooleanParser"));
		case DOUBLE:
			return parserOverride.orElse(parsers.get("DoubleParser"));
		case INSTANT:
			return parserOverride.orElse(parsers.get("InstantParser"));
		case INTEGER:
			return parserOverride.orElse(parsers.get("IntegerParser"));
		case LONG:
			return parserOverride.orElse(parsers.get("LongParser"));
		case STRING_LIST:
			return parserOverride.orElse(parsers.get("StringListParser"));
		case STRING_SET:
			return parserOverride.orElse(parsers.get("StringSetParser"));
		case URL:
			return parserOverride.orElse(parsers.get("UrlParser"));
		default:
			assert (!StringUtils.isEmpty(parserOverrideClassName));
			return parserOverride.get();
		}

	}

	private ParsedProperty<Object> parse(final Attribute p) {
		final AttributeValueParser<?> parser = getParser(p.parseTo(), p.parserOverride());
		if (parser == null) {
			throw new RuntimeException("No registered AttributeValueParser implementation for " + p.parserOverride());
		}

		return new ParsedProperty<>(p.name(), parser.parse(p.value()));
	}

	/**
	 * <p>
	 * Turns a {@link org.springframework.security.test.context.support.oauth2.Attribute @Attribute} array into a
	 * {@link java.util.Map Map&lt;String, Object&gt;} as required for
	 * {@link org.springframework.security.oauth2.jwt.Jwt JWT} headers and claims.
	 * </p>
	 * <p>
	 * Process highlights:
	 * </p>
	 * <ul>
	 * <li>each {@link org.springframework.security.test.context.support.oauth2.Attribute#value() value()} is parsed
	 * according to {@link org.springframework.security.test.context.support.oauth2.Attribute#parserOverride()
	 * parser()}</li>
	 * <li>obtained values are associated with
	 * {@link org.springframework.security.test.context.support.oauth2.Attribute#name() name()}</li>
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
	 * Instantiates default {@link org.springframework.security.test.context.support.oauth2.AttributeValueParser
	 * AttributeValueParser}s plus all provided ones (using default constructor)
	 *
	 * @param additionalParserNames {@link org.springframework.security.test.context.support.oauth2.AttributeValueParser
	 * AttributeValueParser} implementations class names to add to
	 * {@link org.springframework.security.test.context.support.oauth2.AttributeParsersHelper#DEFAULT_PARSERS default
	 * ones}
	 * @return helper instance with provided parsers plus default ones
	 */
	public static AttributeParsersHelper withDefaultParsers(final String... additionalParserNames) {
		final Map<String, AttributeValueParser<?>> baseParsers = new HashMap<>(9);

		baseParsers.put("NoOpParser", (final String value) -> value);
		baseParsers.put(
				"BooleanParser",
				(final String value) -> StringUtils.isEmpty(value) ? null : Boolean.valueOf(value));
		baseParsers
				.put("DoubleParser", (final String value) -> StringUtils.isEmpty(value) ? null : Double.valueOf(value));
		baseParsers
				.put("InstantParser", (final String value) -> StringUtils.isEmpty(value) ? null : Instant.parse(value));
		baseParsers.put(
				"IntegerParser",
				(final String value) -> StringUtils.isEmpty(value) ? null : Integer.valueOf(value));
		baseParsers.put("LongParser", (final String value) -> StringUtils.isEmpty(value) ? null : Long.valueOf(value));
		baseParsers.put(
				"StringListParser",
				(final String value) -> StringUtils.isEmpty(value) ? Collections.emptyList()
						: Collections.singletonList(value));
		baseParsers.put(
				"StringSetParser",
				(final String value) -> StringUtils.isEmpty(value) ? Collections.emptySet()
						: Collections.singleton(value));
		baseParsers.put("UrlParser", (final String value) -> {
			try {
				return (StringUtils.isEmpty(value)) ? null : new URL(value);
			} catch (final MalformedURLException e) {
				throw new RuntimeException(e);
			}
		});

		return new AttributeParsersHelper(baseParsers, additionalParserNames);
	}

	/**
	 * Instantiates all provided {@link org.springframework.security.test.context.support.oauth2.AttributeValueParser
	 * AttributeValueParser}s using default constructor
	 *
	 * @param allParserNames {@link org.springframework.security.test.context.support.oauth2.AttributeValueParser
	 * AttributeValueParser} implementations class names
	 * @return helper instance with provided parsers only
	 */
	public static AttributeParsersHelper withoutDefaultParsers(final String... allParserNames) {
		return new AttributeParsersHelper(Collections.emptyMap(), allParserNames);
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
