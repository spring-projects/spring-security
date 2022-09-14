/*
 * Copyright 2015-2021 the original author or authors.
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
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.fasterxml.jackson.annotation.JacksonAnnotation;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.DatabindContext;
import com.fasterxml.jackson.databind.DeserializationConfig;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.cfg.MapperConfig;
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import com.fasterxml.jackson.databind.jsontype.NamedType;
import com.fasterxml.jackson.databind.jsontype.PolymorphicTypeValidator;
import com.fasterxml.jackson.databind.jsontype.TypeIdResolver;
import com.fasterxml.jackson.databind.jsontype.TypeResolverBuilder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.core.log.LogMessage;
import org.springframework.util.ClassUtils;

/**
 * This utility class will find all the SecurityModules in classpath.
 *
 * <p>
 * <pre>
 *     ObjectMapper mapper = new ObjectMapper();
 *     mapper.registerModules(SecurityJackson2Modules.getModules());
 * </pre> Above code is equivalent to
 * <p>
 * <pre>
 *     ObjectMapper mapper = new ObjectMapper();
 *     mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL, JsonTypeInfo.As.PROPERTY);
 *     mapper.registerModule(new CoreJackson2Module());
 *     mapper.registerModule(new CasJackson2Module());
 *     mapper.registerModule(new WebJackson2Module());
 *     mapper.registerModule(new WebServletJackson2Module());
 *     mapper.registerModule(new WebServerJackson2Module());
 *     mapper.registerModule(new OAuth2ClientJackson2Module());
 *     mapper.registerModule(new Saml2Jackson2Module());
 * </pre>
 *
 * @author Jitendra Singh.
 * @since 4.2
 */
public final class SecurityJackson2Modules {

	private static final Log logger = LogFactory.getLog(SecurityJackson2Modules.class);

	private static final List<String> securityJackson2ModuleClasses = Arrays.asList(
			"org.springframework.security.jackson2.CoreJackson2Module",
			"org.springframework.security.cas.jackson2.CasJackson2Module",
			"org.springframework.security.web.jackson2.WebJackson2Module",
			"org.springframework.security.web.server.jackson2.WebServerJackson2Module");

	private static final String webServletJackson2ModuleClass = "org.springframework.security.web.jackson2.WebServletJackson2Module";

	private static final String oauth2ClientJackson2ModuleClass = "org.springframework.security.oauth2.client.jackson2.OAuth2ClientJackson2Module";

	private static final String javaTimeJackson2ModuleClass = "com.fasterxml.jackson.datatype.jsr310.JavaTimeModule";

	private static final String ldapJackson2ModuleClass = "org.springframework.security.ldap.jackson2.LdapJackson2Module";

	private static final String saml2Jackson2ModuleClass = "org.springframework.security.saml2.jackson2.Saml2Jackson2Module";

	private SecurityJackson2Modules() {
	}

	public static void enableDefaultTyping(ObjectMapper mapper) {
		if (mapper != null) {
			TypeResolverBuilder<?> typeBuilder = mapper.getDeserializationConfig().getDefaultTyper(null);
			if (typeBuilder == null) {
				mapper.setDefaultTyping(createAllowlistedDefaultTyping());
			}
		}
	}

	@SuppressWarnings("unchecked")
	private static Module loadAndGetInstance(String className, ClassLoader loader) {
		try {
			Class<? extends Module> securityModule = (Class<? extends Module>) ClassUtils.forName(className, loader);
			if (securityModule != null) {
				logger.debug(LogMessage.format("Loaded module %s, now registering", className));
				return securityModule.newInstance();
			}
		}
		catch (Exception ex) {
			logger.debug(LogMessage.format("Cannot load module %s", className), ex);
		}
		return null;
	}

	/**
	 * @param loader the ClassLoader to use
	 * @return List of available security modules in classpath.
	 */
	public static List<Module> getModules(ClassLoader loader) {
		List<Module> modules = new ArrayList<>();
		for (String className : securityJackson2ModuleClasses) {
			addToModulesList(loader, modules, className);
		}
		if (ClassUtils.isPresent("jakarta.servlet.http.Cookie", loader)) {
			addToModulesList(loader, modules, webServletJackson2ModuleClass);
		}
		if (ClassUtils.isPresent("org.springframework.security.oauth2.client.OAuth2AuthorizedClient", loader)) {
			addToModulesList(loader, modules, oauth2ClientJackson2ModuleClass);
		}
		if (ClassUtils.isPresent(javaTimeJackson2ModuleClass, loader)) {
			addToModulesList(loader, modules, javaTimeJackson2ModuleClass);
		}
		if (ClassUtils.isPresent(ldapJackson2ModuleClass, loader)) {
			addToModulesList(loader, modules, ldapJackson2ModuleClass);
		}
		if (ClassUtils.isPresent(saml2Jackson2ModuleClass, loader)) {
			addToModulesList(loader, modules, saml2Jackson2ModuleClass);
		}
		return modules;
	}

	/**
	 * @param loader the ClassLoader to use
	 * @param modules list of the modules to add
	 * @param className name of the class to instantiate
	 */
	private static void addToModulesList(ClassLoader loader, List<Module> modules, String className) {
		Module module = loadAndGetInstance(className, loader);
		if (module != null) {
			modules.add(module);
		}
	}

	/**
	 * Creates a TypeResolverBuilder that restricts allowed types.
	 * @return a TypeResolverBuilder that restricts allowed types.
	 */
	private static TypeResolverBuilder<? extends TypeResolverBuilder> createAllowlistedDefaultTyping() {
		TypeResolverBuilder<? extends TypeResolverBuilder> result = new AllowlistTypeResolverBuilder(
				ObjectMapper.DefaultTyping.NON_FINAL);
		result = result.init(JsonTypeInfo.Id.CLASS, null);
		result = result.inclusion(JsonTypeInfo.As.PROPERTY);
		return result;
	}

	/**
	 * An implementation of {@link ObjectMapper.DefaultTypeResolverBuilder} that inserts
	 * an {@code allow all} {@link PolymorphicTypeValidator} and overrides the
	 * {@code TypeIdResolver}
	 *
	 * @author Rob Winch
	 */
	static class AllowlistTypeResolverBuilder extends ObjectMapper.DefaultTypeResolverBuilder {

		AllowlistTypeResolverBuilder(ObjectMapper.DefaultTyping defaultTyping) {
			super(defaultTyping,
					// we do explicit validation in the TypeIdResolver
					BasicPolymorphicTypeValidator.builder().allowIfSubType(Object.class).build());
		}

		@Override
		protected TypeIdResolver idResolver(MapperConfig<?> config, JavaType baseType,
				PolymorphicTypeValidator subtypeValidator, Collection<NamedType> subtypes, boolean forSer,
				boolean forDeser) {
			TypeIdResolver result = super.idResolver(config, baseType, subtypeValidator, subtypes, forSer, forDeser);
			return new AllowlistTypeIdResolver(result);
		}

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
		public String idFromValue(Object value) {
			return this.delegate.idFromValue(value);
		}

		@Override
		public String idFromValueAndType(Object value, Class<?> suggestedType) {
			return this.delegate.idFromValueAndType(value, suggestedType);
		}

		@Override
		public String idFromBaseType() {
			return this.delegate.idFromBaseType();
		}

		@Override
		public JavaType typeFromId(DatabindContext context, String id) throws IOException {
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
