package org.springframework.security.config;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.providers.dao.DaoAuthenticationProvider;
import org.springframework.security.providers.encoding.Md4PasswordEncoder;
import org.springframework.security.providers.encoding.Md5PasswordEncoder;
import org.springframework.security.providers.encoding.PasswordEncoder;
import org.springframework.security.providers.encoding.PlaintextPasswordEncoder;
import org.springframework.security.providers.encoding.ShaPasswordEncoder;
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

	static final String ATT_DATA_SOURCE = "dataSource";
	static final String ATT_ID = "id";

	static final String ATT_CREATE_PROVIDER = "createProvider";
	static final String DEF_CREATE_PROVIDER = "true";

	static final String ATT_HASH = "hash";
	static final String DEF_HASH_PLAINTEXT = "plaintext";
	static final String OPT_HASH_SHA_HEX = "sha:hex";
	static final String OPT_HASH_SHA_BASE64 = "sha:base64";
	static final String OPT_HASH_MD4_HEX = "md4:hex";
	static final String OPT_HASH_MD4_BASE64 = "md4:base64";
	static final String OPT_HASH_MD5_HEX = "md5:hex";
	static final String OPT_HASH_MD5_BASE64 = "md5:base64";
	
    public BeanDefinition parse(Element element, ParserContext parserContext) {
        boolean createProvider = true;
    	String createProviderAtt = element.getAttribute(ATT_CREATE_PROVIDER);
        if (StringUtils.hasText(createProviderAtt) && "false".equals(createProviderAtt)) {
        	createProvider = false;
        }
        
    	if (createProvider) {
            ConfigUtils.registerProviderManagerIfNecessary(parserContext);
    	}

        Element userServiceElt = DomUtils.getChildElementByTagName(element, Elements.USER_SERVICE);
        Element jdbcUserServiceElt = DomUtils.getChildElementByTagName(element, Elements.JDBC_USER_SERVICE);
        Element customUserServiceElt = DomUtils.getChildElementByTagName(element, Elements.CUSTOM_USER_SERVICE);

        if (userServiceElt != null) {
            BeanDefinition userDetailsService = new UserServiceBeanDefinitionParser().parse(userServiceElt, parserContext);
            createDaoAuthenticationProviderIfRequired(createProvider, userServiceElt.getAttribute(ATT_HASH), userDetailsService, parserContext);
        }
        
        if (jdbcUserServiceElt != null) {
        	// TODO: Set authenticationManager property
        	// TODO: Have some sensible fallback if dataSource not specified, eg autowire
            BeanDefinitionBuilder builder = BeanDefinitionBuilder.rootBeanDefinition(JdbcUserDetailsManager.class);
            String dataSource = jdbcUserServiceElt.getAttribute(ATT_DATA_SOURCE);
        	// An explicit dataSource was specified, so use it
            builder.addPropertyReference("dataSource", dataSource);
            parserContext.getRegistry().registerBeanDefinition(BeanIds.JDBC_USER_DETAILS_MANAGER, builder.getBeanDefinition());
            createDaoAuthenticationProviderIfRequired(createProvider, jdbcUserServiceElt.getAttribute(ATT_HASH), builder.getBeanDefinition(), parserContext);
        }
        
        if (customUserServiceElt != null) {
            String id = customUserServiceElt.getAttribute(ATT_ID);
            BeanDefinition userDetailsService = parserContext.getRegistry().getBeanDefinition(id);
            createDaoAuthenticationProviderIfRequired(createProvider, customUserServiceElt.getAttribute(ATT_HASH), userDetailsService, parserContext);
        }
        
        return null;
    }
    
    private void createDaoAuthenticationProviderIfRequired(boolean createProvider, String hash, BeanDefinition userDetailsService, ParserContext parserContext) {
        if (createProvider) {
        	if (!StringUtils.hasText(hash)) {
        		hash = DEF_HASH_PLAINTEXT;
        	}
            RootBeanDefinition authProvider = new RootBeanDefinition(DaoAuthenticationProvider.class);
            authProvider.getPropertyValues().addPropertyValue("userDetailsService", userDetailsService);
            
            PasswordEncoder pwdEnc = null;
            if (OPT_HASH_MD4_HEX.equals(hash)) {
            	pwdEnc = new Md4PasswordEncoder();
            	((Md4PasswordEncoder)pwdEnc).setEncodeHashAsBase64(false);
            } else if (OPT_HASH_MD4_BASE64.equals(hash)) {
            	pwdEnc = new Md4PasswordEncoder();
            	((Md4PasswordEncoder)pwdEnc).setEncodeHashAsBase64(true);
            } else if (OPT_HASH_MD5_HEX.equals(hash)) {
            	pwdEnc = new Md5PasswordEncoder();
            	((Md5PasswordEncoder)pwdEnc).setEncodeHashAsBase64(false);
            } else if (OPT_HASH_MD5_BASE64.equals(hash)) {
            	pwdEnc = new Md5PasswordEncoder();
            	((Md5PasswordEncoder)pwdEnc).setEncodeHashAsBase64(true);
            } else if (OPT_HASH_SHA_HEX.equals(hash)) {
            	pwdEnc = new ShaPasswordEncoder();
            	((ShaPasswordEncoder)pwdEnc).setEncodeHashAsBase64(false);
            } else if (OPT_HASH_SHA_BASE64.equals(hash)) {
            	pwdEnc = new ShaPasswordEncoder();
            	((ShaPasswordEncoder)pwdEnc).setEncodeHashAsBase64(true);
            } else {
            	pwdEnc = new PlaintextPasswordEncoder();
            }
            authProvider.getPropertyValues().addPropertyValue("passwordEncoder", pwdEnc);
            
            ConfigUtils.getRegisteredProviders(parserContext).add(authProvider);
        }
    }
}
