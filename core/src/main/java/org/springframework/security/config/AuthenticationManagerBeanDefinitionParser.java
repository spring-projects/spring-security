package org.springframework.security.config;

import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.util.StringUtils;

import org.w3c.dom.Element;

/**
 * Registers an alias name for the default ProviderManager used by the namespace
 * configuration, allowing users to reference it in their beans and clearly see where the name is
 * coming from. Also allows the ConcurrentSessionController to be set on the ProviderManager.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class AuthenticationManagerBeanDefinitionParser implements BeanDefinitionParser {
    private static final String ATT_SESSION_CONTROLLER_REF = "session-controller-ref";
	private static final String ATT_ALIAS = "alias";

    public BeanDefinition parse(Element element, ParserContext parserContext) {
    	ConfigUtils.registerProviderManagerIfNecessary(parserContext);
    	
        String alias = element.getAttribute(ATT_ALIAS);

        if (!StringUtils.hasText(alias)) {
            parserContext.getReaderContext().error(ATT_ALIAS + " is required.", element );
        }
        
        String sessionControllerRef = element.getAttribute(ATT_SESSION_CONTROLLER_REF);
        
        if (StringUtils.hasText(sessionControllerRef)) {
        	BeanDefinition authManager = parserContext.getRegistry().getBeanDefinition(BeanIds.AUTHENTICATION_MANAGER);
            ConfigUtils.setSessionControllerOnAuthenticationManager(parserContext, 
            		BeanIds.CONCURRENT_SESSION_CONTROLLER, element);
        	authManager.getPropertyValues().addPropertyValue("sessionController", 
        			new RuntimeBeanReference(sessionControllerRef));
            RootBeanDefinition sessionRegistryInjector = new RootBeanDefinition(SessionRegistryInjectionBeanPostProcessor.class);
            sessionRegistryInjector.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
            sessionRegistryInjector.getConstructorArgumentValues().addGenericArgumentValue(sessionControllerRef);
        	
        	parserContext.getRegistry().registerBeanDefinition(BeanIds.SESSION_REGISTRY_INJECTION_POST_PROCESSOR, sessionRegistryInjector);
        }

        parserContext.getRegistry().registerAlias(BeanIds.AUTHENTICATION_MANAGER, alias);

        return null;
    }    
}
