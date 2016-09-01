/*
 * Copyright 2015-2016 the original author or authors.
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

package org.springframework.security.jackson2;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.TypeResolverBuilder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.util.ClassUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * This utility class will find all the SecurityModules in classpath.
 *
 * <p>
 * <pre>
 *     ObjectMapper mapper = new ObjectMapper();
 *     mapper.registerModules(SecurityJacksonModules.getModules());
 * </pre>
 * Above code is equivalent to
 * <p>
 * <pre>
 *     ObjectMapper mapper = new ObjectMapper();
 *     mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL, JsonTypeInfo.As.PROPERTY);
 *     mapper.registerModule(new CoreJackson2Module());
 *     mapper.registerModule(new CasJackson2Module());
 *     mapper.registerModule(new WebJackson2Module());
 * </pre>
 *
 * @author Jitendra Singh.
 * @since 4.2
 */
public final class SecurityJacksonModules {

	private static final Log logger = LogFactory.getLog(SecurityJacksonModules.class);
	private static final List<String> securityJackson2ModuleClasses = Arrays.asList(
			"org.springframework.security.jackson2.CoreJackson2Module",
			"org.springframework.security.cas.jackson2.CasJackson2Module",
			"org.springframework.security.web.jackson2.WebJackson2Module"
	);

	private SecurityJacksonModules() {
	}

	public static void enableDefaultTyping(ObjectMapper mapper) {
		if(mapper != null) {
			TypeResolverBuilder<?> typeBuilder = mapper.getDeserializationConfig().getDefaultTyper(null);
			if (typeBuilder == null) {
				mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL, JsonTypeInfo.As.PROPERTY);
			}
		}
	}

	@SuppressWarnings("unchecked")
	private static Module loadAndGetInstance(String className, ClassLoader loader) {
		Module instance = null;
		try {
			Class<? extends Module> securityModule = (Class<? extends Module>) ClassUtils.forName(className, loader);
			if (securityModule != null) {
				if(logger.isDebugEnabled()) {
					logger.debug("Loaded module " + className + ", now registering");
				}
				instance = securityModule.newInstance();
			}
		} catch (Exception e) {
			if(logger.isDebugEnabled()) {
				logger.debug("Cannot load module " + className, e);
			}
		}
		return instance;
	}

	/**
	 * @param loader the ClassLoader to use
	 * @return List of available security modules in classpath.
	 */
	public static List<Module> getModules(ClassLoader loader) {
		List<Module> modules = new ArrayList<Module>();
		for (String className : securityJackson2ModuleClasses) {
			Module module = loadAndGetInstance(className, loader);
			if (module != null) {
				modules.add(module);
			}
		}
		return modules;
	}
}
