package org.springframework.security.config;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.providers.dao.DaoAuthenticationProvider;
import org.springframework.security.userdetails.jdbc.JdbcUserDetailsManager;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

/**
 * Processes the top-level "repository" element.
 * 
 * <p>A "repository" element is used to indicate a UserDetailsService or equivalent.
 * 
 * @author Ben Alex
 * @version $Id$
 */
class RepositoryBeanDefinitionParser implements BeanDefinitionParser {

	private static final String ATT_CREATE_PROVIDER = "createProvider";
	private static final String DEF_CREATE_PROVIDER = "true";
	private static final String ATT_DATA_SOURCE = "dataSource";
	private static final String ATT_ID = "id";
	
    public BeanDefinition parse(Element element, ParserContext parserContext) {
        boolean createProvider = true;
    	String createProviderAtt = element.getAttribute(ATT_CREATE_PROVIDER);
        if (StringUtils.hasText(createProviderAtt) && "false".equals(createProviderAtt)) {
        	createProvider = false;
        }
        
    	if (createProvider) {
            ConfigUtils.registerProviderManagerIfNecessary(parserContext);
    	}

        Element userServiceElt = DomUtils.getChildElementByTagName(element, Elements.ELT_USER_SERVICE);
        Element jdbcUserServiceElt = DomUtils.getChildElementByTagName(element, Elements.ELT_JDBC_USER_SERVICE);
        Element customUserServiceElt = DomUtils.getChildElementByTagName(element, Elements.ELT_CUSTOM_USER_SERVICE);

        if (userServiceElt != null) {
            BeanDefinition userDetailsService = new UserServiceBeanDefinitionParser().parse(userServiceElt, parserContext);
            createDaoAuthenticationProviderIfRequired(createProvider, userDetailsService, parserContext);
        }
        
        if (jdbcUserServiceElt != null) {
        	// TODO: Set authenticationManager property
        	// TODO: Have some sensible fallback if dataSource not specified, eg autowire
            BeanDefinitionBuilder builder = BeanDefinitionBuilder.rootBeanDefinition(JdbcUserDetailsManager.class);
            String dataSource = jdbcUserServiceElt.getAttribute(ATT_DATA_SOURCE);
        	// An explicit dataSource was specified, so use it
            builder.addPropertyReference("dataSource", dataSource);
            parserContext.getRegistry().registerBeanDefinition(BeanIds.JDBC_USER_DETAILS_MANAGER, builder.getBeanDefinition());
            createDaoAuthenticationProviderIfRequired(createProvider, builder.getBeanDefinition(), parserContext);
        }
        
        if (customUserServiceElt != null) {
            String id = customUserServiceElt.getAttribute(ATT_ID);
            BeanDefinition userDetailsService = parserContext.getRegistry().getBeanDefinition(id);
            createDaoAuthenticationProviderIfRequired(createProvider, userDetailsService, parserContext);
        }
        
        return null;
    }
    
    private void createDaoAuthenticationProviderIfRequired(boolean createProvider, BeanDefinition userDetailsService, ParserContext parserContext) {
        if (createProvider) {
            RootBeanDefinition authProvider = new RootBeanDefinition(DaoAuthenticationProvider.class);
            authProvider.getPropertyValues().addPropertyValue("userDetailsService", userDetailsService);
            ConfigUtils.getRegisteredProviders(parserContext).add(authProvider);
        }
    }
}
