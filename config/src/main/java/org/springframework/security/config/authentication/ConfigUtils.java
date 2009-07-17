package org.springframework.security.config.authentication;

import java.util.ArrayList;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.parsing.BeanComponentDefinition;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.config.BeanIds;
import org.w3c.dom.Element;

/**
 * Utility methods used internally by the Spring Security namespace configuration code.
 *
 * @author Luke Taylor
 * @author Ben Alex
 * @version $Id: WebConfigUtils.java 3770 2009-07-15 23:09:47Z ltaylor $
 */
public abstract class ConfigUtils {

    /**
     * Creates and registers the bean definition for the default ProviderManager instance and returns
     * the BeanDefinition for it. This method will typically be called when registering authentication providers
     * using the &lt;security:provider /> tag or by other beans which have a dependency on the
     * authentication manager.
     * @param element the source element under which this bean should be registered.
     */
    public static void registerProviderManagerIfNecessary(ParserContext pc, Element element) {
        if(pc.getRegistry().containsBeanDefinition(BeanIds.AUTHENTICATION_MANAGER)) {
            return;
        }

        RootBeanDefinition authManager = new RootBeanDefinition(NamespaceAuthenticationManager.class);
        authManager.getPropertyValues().addPropertyValue("providerBeanNames", new ArrayList<String>());
        authManager.setSource(pc.extractSource(element.getOwnerDocument().getFirstChild()));
        pc.getRegistry().registerBeanDefinition(BeanIds.AUTHENTICATION_MANAGER, authManager);
        pc.registerBeanComponent(new BeanComponentDefinition(authManager, BeanIds.AUTHENTICATION_MANAGER));
    }

    @SuppressWarnings("unchecked")
    public static void addAuthenticationProvider(ParserContext parserContext, String beanName, Element element) {
        registerProviderManagerIfNecessary(parserContext, element);
        BeanDefinition authManager = parserContext.getRegistry().getBeanDefinition(BeanIds.AUTHENTICATION_MANAGER);
        ((ArrayList) authManager.getPropertyValues().getPropertyValue("providerBeanNames").getValue()).add(beanName);
    }
}
