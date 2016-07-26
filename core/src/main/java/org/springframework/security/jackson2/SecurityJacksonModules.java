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
import org.springframework.util.ObjectUtils;

/**
 * This utility class will find and register SecurityModules and configure ObjectMapper.
 * If default typing isn't enabled, then this class will enabled default typing.
 *
 * <pre>
 *     ObjectMapper mapper = new ObjectMapper();
 *     SecurityJacksonModules.registerModules(mapper);
 * </pre>
 *
 * Above code is equivalent to
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

	private SecurityJacksonModules() {
	}

	public static void enableDefaultTyping(ObjectMapper mapper) {
		TypeResolverBuilder<?> typeBuilder = mapper.getDeserializationConfig().getDefaultTyper(null);
		if (ObjectUtils.isEmpty(typeBuilder)) {
			mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL, JsonTypeInfo.As.PROPERTY);
		}
	}

	private static void findAndRegisterSecurityModuleClass(ObjectMapper mapper, String className) {
		try {
			logger.debug("Loading module " + className);
			Class<? extends Module> casModuleClass = (Class<? extends Module>) ClassUtils.forName(className, ClassUtils.getDefaultClassLoader());
			if (!ObjectUtils.isEmpty(casModuleClass)) {
				logger.debug("Loaded module " + className + ", now registering");
				mapper.registerModule(casModuleClass.newInstance());
			}
		} catch (ClassNotFoundException e) {
			logger.warn("Module class not found : "+e.getMessage());
		} catch (InstantiationException e) {
			logger.error(e.getMessage());
		} catch (IllegalAccessException e) {
			logger.error(e.getMessage());
		}
	}

	public static void registerModules(ObjectMapper mapper) {
		enableDefaultTyping(mapper);
		mapper.registerModule(new CoreJackson2Module());
		findAndRegisterSecurityModuleClass(mapper, "org.springframework.security.cas.jackson2.CasJackson2Module");
		findAndRegisterSecurityModuleClass(mapper, "org.springframework.security.web.jackson2.WebJackson2Module");
	}
}
