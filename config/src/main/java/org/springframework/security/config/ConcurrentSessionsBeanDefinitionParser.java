package org.springframework.security.config;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.parsing.BeanComponentDefinition;
import org.springframework.beans.factory.parsing.CompositeComponentDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.concurrent.ConcurrentSessionControllerImpl;
import org.springframework.security.authentication.concurrent.SessionRegistryImpl;
import org.springframework.security.web.authentication.concurrent.ConcurrentSessionFilter;
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
    static final String ATT_SESSION_REGISTRY_ALIAS = "session-registry-alias";
    static final String ATT_SESSION_REGISTRY_REF = "session-registry-ref";

    public BeanDefinition parse(Element element, ParserContext pc) {
        CompositeComponentDefinition compositeDef =
            new CompositeComponentDefinition(element.getTagName(), pc.extractSource(element));
        pc.pushContainingComponent(compositeDef);

        BeanDefinitionRegistry beanRegistry = pc.getRegistry();

        String sessionRegistryId = element.getAttribute(ATT_SESSION_REGISTRY_REF);

        if (!StringUtils.hasText(sessionRegistryId)) {
            // Register an internal SessionRegistryImpl if no external reference supplied.
            RootBeanDefinition sessionRegistry = new RootBeanDefinition(SessionRegistryImpl.class);
            sessionRegistryId = pc.getReaderContext().registerWithGeneratedName(sessionRegistry);
            pc.registerComponent(new BeanComponentDefinition(sessionRegistry, sessionRegistryId));
        }

        String registryAlias = element.getAttribute(ATT_SESSION_REGISTRY_ALIAS);
        if (StringUtils.hasText(registryAlias)) {
            beanRegistry.registerAlias(sessionRegistryId, registryAlias);
        }

        BeanDefinitionBuilder filterBuilder =
                BeanDefinitionBuilder.rootBeanDefinition(ConcurrentSessionFilter.class);
        filterBuilder.addPropertyReference("sessionRegistry", sessionRegistryId);

        Object source = pc.extractSource(element);
        filterBuilder.getRawBeanDefinition().setSource(source);
        filterBuilder.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);

        String expiryUrl = element.getAttribute(ATT_EXPIRY_URL);

        if (StringUtils.hasText(expiryUrl)) {
            ConfigUtils.validateHttpRedirect(expiryUrl, pc, source);
            filterBuilder.addPropertyValue("expiredUrl", expiryUrl);
        }

        pc.popAndRegisterContainingComponent();

        return filterBuilder.getBeanDefinition();
    }
}
