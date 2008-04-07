package org.springframework.security.config;

import org.springframework.beans.BeansException;
import org.springframework.beans.PropertyValue;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.parsing.BeanComponentDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.core.Ordered;
import org.springframework.security.providers.dao.DaoAuthenticationProvider;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

/**
 * Wraps a UserDetailsService bean with a DaoAuthenticationProvider and registers the latter with the
 * ProviderManager.
 *
 * @author Luke Taylor
 * @version $Id$
 */
class AuthenticationProviderBeanDefinitionParser implements BeanDefinitionParser {
    private static String ATT_USER_DETAILS_REF = "user-service-ref";

    public BeanDefinition parse(Element element, ParserContext parserContext) {
        RootBeanDefinition authProvider = new RootBeanDefinition(DaoAuthenticationProvider.class);
        authProvider.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
        authProvider.setSource(parserContext.extractSource(element));

        Element passwordEncoderElt = DomUtils.getChildElementByTagName(element, Elements.PASSWORD_ENCODER);

        if (passwordEncoderElt != null) {
            PasswordEncoderParser pep = new PasswordEncoderParser(passwordEncoderElt, parserContext);
            authProvider.getPropertyValues().addPropertyValue("passwordEncoder", pep.getPasswordEncoder());

            if (pep.getSaltSource() != null) {
                authProvider.getPropertyValues().addPropertyValue("saltSource", pep.getSaltSource());
            }
        }

        Element userServiceElt = DomUtils.getChildElementByTagName(element, Elements.USER_SERVICE);
        Element jdbcUserServiceElt = DomUtils.getChildElementByTagName(element, Elements.JDBC_USER_SERVICE);
        Element ldapUserServiceElt = DomUtils.getChildElementByTagName(element, Elements.LDAP_USER_SERVICE);

        // We need to register the provider to access it in the post processor to check if it has a cache
        final String id = parserContext.getReaderContext().generateBeanName(authProvider);
        parserContext.getRegistry().registerBeanDefinition(id, authProvider);                    
        parserContext.registerComponent(new BeanComponentDefinition(authProvider, id));
        
        String ref = element.getAttribute(ATT_USER_DETAILS_REF);        
        
        if (StringUtils.hasText(ref)) {        	
            if (userServiceElt != null || jdbcUserServiceElt != null || ldapUserServiceElt != null) {
                parserContext.getReaderContext().error("The " + ATT_USER_DETAILS_REF + " attribute cannot be used in combination with child" +
                        "elements '" + Elements.USER_SERVICE + "', '" + Elements.JDBC_USER_SERVICE + "' or '" +
                        Elements.LDAP_USER_SERVICE + "'", element);
            }
        } else {
	        // Use the child elements to create the UserDetailsService
	        AbstractUserDetailsServiceBeanDefinitionParser parser = null;
	        Element elt = null;
	
	        if (userServiceElt != null) {
	        	elt = userServiceElt;
	        	parser = new UserServiceBeanDefinitionParser();
	        } else if (jdbcUserServiceElt != null) {
	        	elt = jdbcUserServiceElt;
	        	parser = new JdbcUserServiceBeanDefinitionParser();
	        } else if (ldapUserServiceElt != null) {
	        	elt = ldapUserServiceElt;
	        	parser = new LdapUserServiceBeanDefinitionParser();
	        } else {
	            parserContext.getReaderContext().error("A user-service is required", element);
	        }
	        
	        parser.parse(elt, parserContext);
	        ref = parser.getId();
        }
        
        authProvider.getPropertyValues().addPropertyValue("userDetailsService", new RuntimeBeanReference(ref));        

        BeanDefinitionBuilder cacheResolverBldr = BeanDefinitionBuilder.rootBeanDefinition(AuthenticationProviderCacheResolver.class);        
        cacheResolverBldr.addConstructorArg(id);
        cacheResolverBldr.addConstructorArg(ref);        
        cacheResolverBldr.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
        BeanDefinition cacheResolver = cacheResolverBldr.getBeanDefinition();
        
        String name = parserContext.getReaderContext().generateBeanName(cacheResolver);
        parserContext.getRegistry().registerBeanDefinition(name , cacheResolver);
        parserContext.registerComponent(new BeanComponentDefinition(cacheResolver, name));
        
        ConfigUtils.getRegisteredProviders(parserContext).add(new RuntimeBeanReference(id));        
        
        return null;
    }
    
    /**
     * Checks whether the registered user service bean has an associated cache and, if so, sets it on the 
     * authentication provider.
     */
    static class AuthenticationProviderCacheResolver implements BeanFactoryPostProcessor, Ordered {
    	private String providerId;
    	private String userServiceId;
    	
		public AuthenticationProviderCacheResolver(String providerId, String userServiceId) {
			this.providerId = providerId;
			this.userServiceId = userServiceId;
		}

		public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
			RootBeanDefinition provider = (RootBeanDefinition) beanFactory.getBeanDefinition(providerId);
			
			String cachingId = userServiceId + AbstractUserDetailsServiceBeanDefinitionParser.CACHING_SUFFIX;
			
			if (beanFactory.containsBeanDefinition(cachingId)) {
				RootBeanDefinition cachingUserService = (RootBeanDefinition) beanFactory.getBeanDefinition(cachingId);
			
				PropertyValue userCacheProperty = cachingUserService.getPropertyValues().getPropertyValue("userCache");
				
				provider.getPropertyValues().addPropertyValue(userCacheProperty);
			}
		}

		public int getOrder() {
			return HIGHEST_PRECEDENCE;
		}
    }
}
