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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jspecify.annotations.Nullable;
import tools.jackson.databind.DefaultTyping;
import tools.jackson.databind.JacksonModule;
import tools.jackson.databind.cfg.MapperBuilder;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import tools.jackson.databind.jsontype.PolymorphicTypeValidator;
import tools.jackson.databind.module.SimpleModule;

import org.springframework.core.log.LogMessage;
import org.springframework.util.ClassUtils;

/**
 * This utility class will find all the Jackson modules contributed by Spring Security in
 * the classpath (except {@code OAuth2AuthorizationServerJacksonModule} and
 * {@code WebauthnJacksonModule}), enable automatic inclusion of type information and
 * configure a {@link PolymorphicTypeValidator} that handles the validation of class
 * names.
 *
 * <p>
 * <pre>
 *     ClassLoader loader = getClass().getClassLoader();
 *     JsonMapper mapper = JsonMapper.builder()
 * 				.addModules(SecurityJacksonModules.getModules(loader))
 * 				.build();
 * </pre>
 *
 * If needed, you can add custom classes to the validation handling.
 * <p>
 * <pre>
 *     ClassLoader loader = getClass().getClassLoader();
 *     BasicPolymorphicTypeValidator.Builder builder = BasicPolymorphicTypeValidator.builder()
 *     			.allowIfSubType(MyCustomType.class);
 *     JsonMapper mapper = JsonMapper.builder()
 * 				.addModules(SecurityJacksonModules.getModules(loader, builder))
 * 	   			.build();
 * </pre>
 *
 * @author Sebastien Deleuze
 * @author Jitendra Singh
 * @since 7.0
 */
public final class SecurityJacksonModules {

	private static final Log logger = LogFactory.getLog(SecurityJacksonModules.class);

	private static final List<String> securityJacksonModuleClasses = Arrays.asList(
			"org.springframework.security.jackson.CoreJacksonModule",
			"org.springframework.security.web.jackson.WebJacksonModule",
			"org.springframework.security.web.server.jackson.WebServerJacksonModule");

	private static final String webServletJacksonModuleClass = "org.springframework.security.web.jackson.WebServletJacksonModule";

	private static final String oauth2ClientJacksonModuleClass = "org.springframework.security.oauth2.client.jackson.OAuth2ClientJacksonModule";

	private static final String ldapJacksonModuleClass = "org.springframework.security.ldap.jackson.LdapJacksonModule";

	private static final String saml2JacksonModuleClass = "org.springframework.security.saml2.jackson.Saml2JacksonModule";

	private static final String casJacksonModuleClass = "org.springframework.security.cas.jackson.CasJacksonModule";

	private static final boolean webServletPresent;

	private static final boolean oauth2ClientPresent;

	private static final boolean ldapJacksonPresent;

	private static final boolean saml2JacksonPresent;

	private static final boolean casJacksonPresent;

	static {

		ClassLoader classLoader = SecurityJacksonModules.class.getClassLoader();
		webServletPresent = ClassUtils.isPresent("jakarta.servlet.http.Cookie", classLoader);
		oauth2ClientPresent = ClassUtils.isPresent("org.springframework.security.oauth2.client.OAuth2AuthorizedClient",
				classLoader);
		ldapJacksonPresent = ClassUtils.isPresent(ldapJacksonModuleClass, classLoader);
		saml2JacksonPresent = ClassUtils.isPresent(saml2JacksonModuleClass, classLoader);
		casJacksonPresent = ClassUtils.isPresent(casJacksonModuleClass, classLoader);
	}

	private SecurityJacksonModules() {
	}

	@SuppressWarnings("unchecked")
	private static @Nullable SecurityJacksonModule loadAndGetInstance(String className, ClassLoader loader) {
		try {
			Class<? extends SecurityJacksonModule> securityModule = (Class<? extends SecurityJacksonModule>) ClassUtils
				.forName(className, loader);
			logger.debug(LogMessage.format("Loaded module %s, now registering", className));
			return securityModule.getConstructor().newInstance();
		}
		catch (Exception ex) {
			logger.debug(LogMessage.format("Cannot load module %s", className), ex);
		}
		return null;
	}

	/**
	 * Return the list of available security modules in classpath, enable automatic
	 * inclusion of type information and configure a default
	 * {@link PolymorphicTypeValidator} that handles the validation of class names.
	 * @param loader the ClassLoader to use
	 * @return List of available security modules in classpath
	 * @see #getModules(ClassLoader, BasicPolymorphicTypeValidator.Builder)
	 */
	public static List<JacksonModule> getModules(ClassLoader loader) {
		return getModules(loader, null);
	}

	/**
	 * Return the list of available security modules in classpath, enable automatic
	 * inclusion of type information and configure a default
	 * {@link PolymorphicTypeValidator} customizable with the provided builder that
	 * handles the validation of class names.
	 * @param loader the ClassLoader to use
	 * @param typeValidatorBuilder the builder to configure custom types allowed in
	 * addition to Spring Security ones
	 * @return List of available security modules in classpath.
	 */
	public static List<JacksonModule> getModules(ClassLoader loader,
			BasicPolymorphicTypeValidator.@Nullable Builder typeValidatorBuilder) {

		List<JacksonModule> modules = new ArrayList<>();
		for (String className : securityJacksonModuleClasses) {
			addToModulesList(loader, modules, className);
		}
		if (webServletPresent) {
			addToModulesList(loader, modules, webServletJacksonModuleClass);
		}
		if (oauth2ClientPresent) {
			addToModulesList(loader, modules, oauth2ClientJacksonModuleClass);
		}
		if (ldapJacksonPresent) {
			addToModulesList(loader, modules, ldapJacksonModuleClass);
		}
		if (saml2JacksonPresent) {
			addToModulesList(loader, modules, saml2JacksonModuleClass);
		}
		if (casJacksonPresent) {
			addToModulesList(loader, modules, casJacksonModuleClass);
		}
		applyPolymorphicTypeValidator(modules, typeValidatorBuilder);
		return modules;
	}

	private static void applyPolymorphicTypeValidator(List<JacksonModule> modules,
			BasicPolymorphicTypeValidator.@Nullable Builder typeValidatorBuilder) {

		BasicPolymorphicTypeValidator.Builder builder = (typeValidatorBuilder != null) ? typeValidatorBuilder
				: BasicPolymorphicTypeValidator.builder();
		for (JacksonModule module : modules) {
			if (module instanceof SecurityJacksonModule securityModule) {
				securityModule.configurePolymorphicTypeValidator(builder);
			}
		}
		modules.add(new SimpleModule() {
			@Override
			public void setupModule(SetupContext context) {
				((MapperBuilder<?, ?>) context.getOwner()).activateDefaultTyping(builder.build(),
						DefaultTyping.NON_FINAL, JsonTypeInfo.As.PROPERTY);
			}
		});
	}

	/**
	 * @param loader the ClassLoader to use
	 * @param modules list of the modules to add
	 * @param className name of the class to instantiate
	 */
	private static void addToModulesList(ClassLoader loader, List<JacksonModule> modules, String className) {
		SecurityJacksonModule module = loadAndGetInstance(className, loader);
		if (module != null) {
			modules.add(module);
		}
	}

}
