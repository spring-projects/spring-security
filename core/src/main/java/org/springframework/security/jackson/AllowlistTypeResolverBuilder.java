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

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import com.fasterxml.jackson.annotation.JacksonAnnotation;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import tools.jackson.databind.DatabindContext;
import tools.jackson.databind.DefaultTyping;
import tools.jackson.databind.DeserializationConfig;
import tools.jackson.databind.JavaType;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import tools.jackson.databind.jsontype.NamedType;
import tools.jackson.databind.jsontype.PolymorphicTypeValidator;
import tools.jackson.databind.jsontype.TypeIdResolver;
import tools.jackson.databind.jsontype.impl.DefaultTypeResolverBuilder;

import org.springframework.core.annotation.AnnotationUtils;

/**
 *
 * An implementation of {@link DefaultTypeResolverBuilder} that inserts an
 * {@code allow all} {@link PolymorphicTypeValidator} and overrides the
 * {@code TypeIdResolver}
 *
 * @author Sebastien Deleuze
 * @author Rob Winch
 * @since 7.0
 */
public class AllowlistTypeResolverBuilder extends DefaultTypeResolverBuilder {

	public AllowlistTypeResolverBuilder() {
		this(DefaultTyping.NON_FINAL);
	}

	public AllowlistTypeResolverBuilder(DefaultTyping defaultTyping) {
		super(// we do explicit validation in the TypeIdResolver
				BasicPolymorphicTypeValidator.builder().allowIfSubType(Object.class).build(), defaultTyping,
				JsonTypeInfo.As.PROPERTY);
	}

	@Override
	protected TypeIdResolver idResolver(DatabindContext ctxt, JavaType baseType,
			PolymorphicTypeValidator subtypeValidator, Collection<NamedType> subtypes, boolean forSer,
			boolean forDeser) {
		TypeIdResolver result = super.idResolver(ctxt, baseType, subtypeValidator, subtypes, forSer, forDeser);
		return new AllowlistTypeIdResolver(result);
	}

	/**
	 * A {@link TypeIdResolver} that delegates to an existing implementation and throws an
	 * IllegalStateException if the class being looked up is not in the allowlist, does
	 * not provide an explicit mixin, and is not annotated with Jackson mappings. See
	 * https://github.com/spring-projects/spring-security/issues/4370
	 */
	static class AllowlistTypeIdResolver implements TypeIdResolver {

		private static final Set<String> ALLOWLIST_CLASS_NAMES;
		static {
			Set<String> names = new HashSet<>();
			names.add("java.util.ArrayList");
			names.add("java.util.Collections$EmptyList");
			names.add("java.util.Collections$EmptyMap");
			names.add("java.util.Collections$UnmodifiableRandomAccessList");
			names.add("java.util.Collections$UnmodifiableSet");
			names.add("java.util.Collections$UnmodifiableMap");
			names.add("java.util.Collections$SingletonList");
			names.add("java.util.Date");
			names.add("java.time.Instant");
			names.add("java.net.URL");
			names.add("java.util.TreeMap");
			names.add("java.util.HashMap");
			names.add("java.util.LinkedHashMap");
			names.add("org.springframework.security.core.context.SecurityContextImpl");
			names.add("java.util.Arrays$ArrayList");
			ALLOWLIST_CLASS_NAMES = Collections.unmodifiableSet(names);
		}

		private final TypeIdResolver delegate;

		AllowlistTypeIdResolver(TypeIdResolver delegate) {
			this.delegate = delegate;
		}

		@Override
		public void init(JavaType baseType) {
			this.delegate.init(baseType);
		}

		@Override
		public String idFromValue(DatabindContext ctxt, Object value) {
			return this.delegate.idFromValue(ctxt, value);
		}

		@Override
		public String idFromValueAndType(DatabindContext ctxt, Object value, Class<?> suggestedType) {
			return this.delegate.idFromValueAndType(ctxt, value, suggestedType);
		}

		@Override
		public String idFromBaseType(DatabindContext ctxt) {
			return this.delegate.idFromBaseType(ctxt);
		}

		@Override
		public JavaType typeFromId(DatabindContext context, String id) {
			DeserializationConfig config = (DeserializationConfig) context.getConfig();
			JavaType result = this.delegate.typeFromId(context, id);
			String className = result.getRawClass().getName();
			if (isInAllowlist(className)) {
				return result;
			}
			boolean isExplicitMixin = config.findMixInClassFor(result.getRawClass()) != null;
			if (isExplicitMixin) {
				return result;
			}
			JacksonAnnotation jacksonAnnotation = AnnotationUtils.findAnnotation(result.getRawClass(),
					JacksonAnnotation.class);
			if (jacksonAnnotation != null) {
				return result;
			}
			throw new IllegalArgumentException("The class with " + id + " and name of " + className
					+ " is not in the allowlist. "
					+ "If you believe this class is safe to deserialize, please provide an explicit mapping using Jackson annotations or by providing a Mixin. "
					+ "If the serialization is only done by a trusted source, you can also enable default typing. "
					+ "See https://github.com/spring-projects/spring-security/issues/4370 for details");
		}

		private boolean isInAllowlist(String id) {
			return ALLOWLIST_CLASS_NAMES.contains(id);
		}

		@Override
		public String getDescForKnownTypeIds() {
			return this.delegate.getDescForKnownTypeIds();
		}

		@Override
		public JsonTypeInfo.Id getMechanism() {
			return this.delegate.getMechanism();
		}

	}

}
