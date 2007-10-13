package org.springframework.security.config;

import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.BeansException;
import org.springframework.security.providers.ProviderManager;
import org.springframework.security.providers.AuthenticationProvider;
import org.springframework.security.vote.AffirmativeBased;
import org.springframework.security.vote.RoleVoter;
import org.springframework.security.vote.AuthenticatedVoter;
import org.springframework.core.Ordered;
import org.w3c.dom.Element;

import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * @author luke
 * @version $Id$
 */
public class AutoConfigBeanDefinitionParser implements BeanDefinitionParser {
    public static final String AUTH_MANAGER_ID = "_authenticationManager";
    public static final String DEFAULT_ACCESS_MANAGER_ID = "_accessManager";    

    public BeanDefinition parse(Element element, ParserContext parserContext) {
        RootBeanDefinition authenticationManager = new RootBeanDefinition(ProviderManager.class);
        BeanDefinitionRegistry registry = parserContext.getRegistry();
        
        registry.registerBeanDefinition(AUTH_MANAGER_ID, authenticationManager);
        registry.registerBeanDefinition("_autoconfigPP", new RootBeanDefinition(AutoConfigPostProcessor.class));

        RootBeanDefinition accessManager = new RootBeanDefinition(AffirmativeBased.class);

        accessManager.getPropertyValues().addPropertyValue("decisionVoters",
                        Arrays.asList(new Object[] {new RoleVoter(), new AuthenticatedVoter()}));

        registry.registerBeanDefinition(DEFAULT_ACCESS_MANAGER_ID, accessManager);
        return null;
    }

    static class AutoConfigPostProcessor implements BeanFactoryPostProcessor, Ordered {

        public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
            BeanDefinition authManager =  beanFactory.getBeanDefinition(AUTH_MANAGER_ID);

            Map providerMap = beanFactory.getBeansOfType(AuthenticationProvider.class);
            List providers = new ArrayList(providerMap.values());

            // TODO: Sort providers according to defined ordering

            authManager.getPropertyValues().addPropertyValue("providers", providers);
        }

        public int getOrder() {
            return HIGHEST_PRECEDENCE;
        }
    }
}
