package org.springframework.security.config;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.parsing.BeanComponentDefinition;
import org.springframework.beans.factory.parsing.CompositeComponentDefinition;
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
    static final String ATT_SESSION_REGISTRY_REF = "session-registry-ref";

    public BeanDefinition parse(Element element, ParserContext parserContext) {
        CompositeComponentDefinition compositeDef =
            new CompositeComponentDefinition(element.getTagName(), parserContext.extractSource(element));
        parserContext.pushContainingComponent(compositeDef);

        BeanDefinitionRegistry beanRegistry = parserContext.getRegistry();

        String sessionRegistryId = element.getAttribute(ATT_SESSION_REGISTRY_REF);

        if (!StringUtils.hasText(sessionRegistryId)) {
            RootBeanDefinition sessionRegistry = new RootBeanDefinition(SessionRegistryImpl.class);
            beanRegistry.registerBeanDefinition(BeanIds.SESSION_REGISTRY, sessionRegistry);
            parserContext.registerComponent(new BeanComponentDefinition(sessionRegistry, BeanIds.SESSION_REGISTRY));
            sessionRegistryId = BeanIds.SESSION_REGISTRY;
        } else {
            // Register the default ID as an alias so that things like session fixation filter can access it
            beanRegistry.registerAlias(sessionRegistryId, BeanIds.SESSION_REGISTRY);
        }

        String registryAlias = element.getAttribute(ATT_SESSION_REGISTRY_ALIAS);
        if (StringUtils.hasText(registryAlias)) {
            beanRegistry.registerAlias(sessionRegistryId, registryAlias);
        }

        BeanDefinitionBuilder filterBuilder =
                BeanDefinitionBuilder.rootBeanDefinition(ConcurrentSessionFilter.class);
        filterBuilder.addPropertyValue("sessionRegistry", new RuntimeBeanReference(sessionRegistryId));

        Object source = parserContext.extractSource(element);
        filterBuilder.getRawBeanDefinition().setSource(source);
        filterBuilder.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);

        String expiryUrl = element.getAttribute(ATT_EXPIRY_URL);

        if (StringUtils.hasText(expiryUrl)) {
            ConfigUtils.validateHttpRedirect(expiryUrl, parserContext, source);
            filterBuilder.addPropertyValue("expiredUrl", expiryUrl);
        }

        BeanDefinitionBuilder controllerBuilder
            = BeanDefinitionBuilder.rootBeanDefinition(ConcurrentSessionControllerImpl.class);
        controllerBuilder.getRawBeanDefinition().setSource(source);
        controllerBuilder.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
        controllerBuilder.addPropertyValue("sessionRegistry", new RuntimeBeanReference(sessionRegistryId));

        String maxSessions = element.getAttribute(ATT_MAX_SESSIONS);

        if (StringUtils.hasText(maxSessions)) {
            controllerBuilder.addPropertyValue("maximumSessions", maxSessions);
        }

        String exceptionIfMaximumExceeded = element.getAttribute(ATT_EXCEPTION_IF_MAX_EXCEEDED);

        if (StringUtils.hasText(exceptionIfMaximumExceeded)) {
            controllerBuilder.addPropertyValue("exceptionIfMaximumExceeded", exceptionIfMaximumExceeded);
        }

        BeanDefinition controller = controllerBuilder.getBeanDefinition();

        beanRegistry.registerBeanDefinition(BeanIds.CONCURRENT_SESSION_CONTROLLER, controller);
        parserContext.registerComponent(new BeanComponentDefinition(controller, BeanIds.CONCURRENT_SESSION_CONTROLLER));
        beanRegistry.registerBeanDefinition(BeanIds.CONCURRENT_SESSION_FILTER, filterBuilder.getBeanDefinition());
        parserContext.registerComponent(new BeanComponentDefinition(filterBuilder.getBeanDefinition(), BeanIds.CONCURRENT_SESSION_FILTER));
        ConfigUtils.addHttpFilter(parserContext, new RuntimeBeanReference(BeanIds.CONCURRENT_SESSION_FILTER));

        ConfigUtils.setSessionControllerOnAuthenticationManager(parserContext, BeanIds.CONCURRENT_SESSION_CONTROLLER, element);

        parserContext.popAndRegisterContainingComponent();

        return null;
    }
}
