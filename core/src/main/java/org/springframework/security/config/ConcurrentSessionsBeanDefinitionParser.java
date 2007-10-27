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
    static final String DEFAULT_SESSION_REGISTRY_ID = "_sessionRegistry";
    static final String DEFAULT_CONCURRENT_SESSION_FILTER_ID = "_concurrentSessionFilter";
    static final String DEFAULT_SESSION_CONTROLLER_ID = "_concurrentSessionController";

    public BeanDefinition parse(Element element, ParserContext parserContext) {
        BeanDefinitionRegistry beanRegistry = parserContext.getRegistry();

        RootBeanDefinition sessionRegistry = new RootBeanDefinition(SessionRegistryImpl.class);
        BeanDefinitionBuilder filterBuilder =
                BeanDefinitionBuilder.rootBeanDefinition(ConcurrentSessionFilter.class);
        BeanDefinitionBuilder controllerBuilder
                = BeanDefinitionBuilder.rootBeanDefinition(ConcurrentSessionControllerImpl.class);
        controllerBuilder.addPropertyValue("sessionRegistry", new RuntimeBeanReference(DEFAULT_SESSION_REGISTRY_ID));
        filterBuilder.addPropertyValue("sessionRegistry", new RuntimeBeanReference(DEFAULT_SESSION_REGISTRY_ID));

        String expiryUrl = element.getAttribute("expiryUrl");

        if (StringUtils.hasText(expiryUrl)) {
            filterBuilder.addPropertyValue("expiryUrl", expiryUrl);
        }

        String maxSessions = element.getAttribute("maxSessions");

        if (StringUtils.hasText(expiryUrl)) {
            controllerBuilder.addPropertyValue("maximumSessions", maxSessions);
        }

        String exceptionIfMaximumExceeded = element.getAttribute("exceptionIfMaximumExceeded");

        if (StringUtils.hasText(expiryUrl)) {
            controllerBuilder.addPropertyValue("exceptionIfMaximumExceeded", exceptionIfMaximumExceeded);
        }

        BeanDefinition controller = controllerBuilder.getBeanDefinition();
        beanRegistry.registerBeanDefinition(DEFAULT_SESSION_REGISTRY_ID, sessionRegistry);
        beanRegistry.registerBeanDefinition(DEFAULT_SESSION_CONTROLLER_ID, controller);
        beanRegistry.registerBeanDefinition(DEFAULT_CONCURRENT_SESSION_FILTER_ID, filterBuilder.getBeanDefinition());

        BeanDefinition providerManager = ConfigUtils.registerProviderManagerIfNecessary(parserContext);

        providerManager.getPropertyValues().addPropertyValue("sessionController", controller);

        return null;
    }
}
