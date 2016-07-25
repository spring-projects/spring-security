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
 * @author Jitendra Singh.
 * @Since 4.2
 */
public final class SecurityJacksonModules {

	private static final Log logger = LogFactory.getLog(SecurityJacksonModules.class);

	private SecurityJacksonModules() {
	}

	private static void enableDefaultTyping(ObjectMapper mapper) {
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
