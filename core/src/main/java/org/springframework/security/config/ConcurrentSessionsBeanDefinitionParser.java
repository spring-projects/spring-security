package org.springframework.security.config;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.concurrent.ConcurrentSessionControllerImpl;
import org.springframework.security.concurrent.ConcurrentSessionFilter;
import org.springframework.security.concurrent.SessionRegistryImpl;
import org.springframework.security.providers.ProviderManager;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * Sets up support for concurrent session support control, creating {@link ConcurrentSessionFilter},
 * {@link SessionRegistryImpl} and {@link ConcurrentSessionControllerImpl}. The session controller is also registered
 * with the default {@link ProviderManager} (which is automatically registered during namespace configuration).
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class ConcurrentSessionsBeanDefinitionParser implements BeanDefinitionParser {

    static final String ATT_EXPIRY_URL = "expired-url";
    static final String ATT_MAX_SESSIONS = "max-sessions";
    static final String ATT_EXCEPTION_IF_MAX_EXCEEDED = "exception-if-maximum-exceeded";
    static final String ATT_SESSION_REGISTRY_ALIAS = "session-registry-alias";    
	
    public BeanDefinition parse(Element element, ParserContext parserContext) {
        BeanDefinitionRegistry beanRegistry = parserContext.getRegistry();

        RootBeanDefinition sessionRegistry = new RootBeanDefinition(SessionRegistryImpl.class);
        BeanDefinitionBuilder filterBuilder =
                BeanDefinitionBuilder.rootBeanDefinition(ConcurrentSessionFilter.class);
        BeanDefinitionBuilder controllerBuilder
                = BeanDefinitionBuilder.rootBeanDefinition(ConcurrentSessionControllerImpl.class);
        controllerBuilder.addPropertyValue("sessionRegistry", new RuntimeBeanReference(BeanIds.SESSION_REGISTRY));
        filterBuilder.addPropertyValue("sessionRegistry", new RuntimeBeanReference(BeanIds.SESSION_REGISTRY));

        Object source = parserContext.extractSource(element);
        filterBuilder.setSource(source);
        controllerBuilder.setSource(source);

        String expiryUrl = element.getAttribute(ATT_EXPIRY_URL);

        if (StringUtils.hasText(expiryUrl)) {
            filterBuilder.addPropertyValue("expiredUrl", expiryUrl);
        }

        String maxSessions = element.getAttribute(ATT_MAX_SESSIONS);

        if (StringUtils.hasText(maxSessions)) {
            controllerBuilder.addPropertyValue("maximumSessions", maxSessions);
        }

        String exceptionIfMaximumExceeded = element.getAttribute(ATT_EXCEPTION_IF_MAX_EXCEEDED);

        if (StringUtils.hasText(exceptionIfMaximumExceeded)) {
            controllerBuilder.addPropertyValue("exceptionIfMaximumExceeded", exceptionIfMaximumExceeded);
        }

        BeanDefinition controller = controllerBuilder.getBeanDefinition();
        beanRegistry.registerBeanDefinition(BeanIds.SESSION_REGISTRY, sessionRegistry);
        
        String registryAlias = element.getAttribute(ATT_SESSION_REGISTRY_ALIAS);
        if (StringUtils.hasText(registryAlias)) {
        	beanRegistry.registerAlias(BeanIds.SESSION_REGISTRY, registryAlias);
        }

        beanRegistry.registerBeanDefinition(BeanIds.CONCURRENT_SESSION_CONTROLLER, controller);
        beanRegistry.registerBeanDefinition(BeanIds.CONCURRENT_SESSION_FILTER, filterBuilder.getBeanDefinition());

        BeanDefinition providerManager = ConfigUtils.registerProviderManagerIfNecessary(parserContext);

        providerManager.getPropertyValues().addPropertyValue("sessionController", controller);

        return null;
    }
}
