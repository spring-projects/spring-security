package org.springframework.security.config;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

/**
 * Ldap authentication provider namespace configuration.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.0
 */
public class LdapProviderBeanDefinitionParser implements BeanDefinitionParser {
    private Log logger = LogFactory.getLog(getClass());
  
    private static final String ATT_USER_DN_PATTERN = "user-dn-pattern";
    private static final String ATT_USER_PASSWORD = "password-attribute";
    private static final String ATT_HASH = PasswordEncoderParser.ATT_HASH; 
    
    private static final String DEF_USER_SEARCH_FILTER = "uid={0}";
    
    private static final String PROVIDER_CLASS = "org.springframework.security.providers.ldap.LdapAuthenticationProvider";
    private static final String BIND_AUTH_CLASS = "org.springframework.security.providers.ldap.authenticator.BindAuthenticator";
    private static final String PASSWD_AUTH_CLASS = "org.springframework.security.providers.ldap.authenticator.PasswordComparisonAuthenticator";

    public BeanDefinition parse(Element elt, ParserContext parserContext) {
        RuntimeBeanReference contextSource = LdapUserServiceBeanDefinitionParser.parseServerReference(elt, parserContext);
        
        BeanDefinition searchBean = LdapUserServiceBeanDefinitionParser.parseSearchBean(elt, parserContext);
        String userDnPattern = elt.getAttribute(ATT_USER_DN_PATTERN);
        
        String[] userDnPatternArray = new String[0];
        
        if (StringUtils.hasText(userDnPattern)) {
            userDnPatternArray = new String[] {userDnPattern};
            // TODO: Validate the pattern and make sure it is a valid DN.
        } else if (searchBean == null) {
            logger.info("No search information or DN pattern specified. Using default search filter '" + DEF_USER_SEARCH_FILTER + "'");
            BeanDefinitionBuilder searchBeanBuilder = BeanDefinitionBuilder.rootBeanDefinition(LdapUserServiceBeanDefinitionParser.LDAP_SEARCH_CLASS); 
            searchBeanBuilder.setSource(elt);
            searchBeanBuilder.addConstructorArg("");
            searchBeanBuilder.addConstructorArg(DEF_USER_SEARCH_FILTER);
            searchBeanBuilder.addConstructorArg(contextSource);
            searchBean = searchBeanBuilder.getBeanDefinition();
        }
        
        BeanDefinitionBuilder authenticatorBuilder = 
        	BeanDefinitionBuilder.rootBeanDefinition(BIND_AUTH_CLASS);
        Element passwordCompareElt = DomUtils.getChildElementByTagName(elt, Elements.LDAP_PASSWORD_COMPARE);
        
        if (passwordCompareElt != null) {
        	authenticatorBuilder = 
            	BeanDefinitionBuilder.rootBeanDefinition(PASSWD_AUTH_CLASS);
            
            String passwordAttribute = passwordCompareElt.getAttribute(ATT_USER_PASSWORD);
            if (StringUtils.hasText(passwordAttribute)) {
            	authenticatorBuilder.addPropertyValue("passwordAttributeName", passwordAttribute);
            }
            
            Element passwordEncoderElement = DomUtils.getChildElementByTagName(passwordCompareElt, Elements.PASSWORD_ENCODER);
            String hash = passwordCompareElt.getAttribute(ATT_HASH);
            
            if (passwordEncoderElement != null) {
                if (StringUtils.hasText(hash)) {
                    parserContext.getReaderContext().warning("Attribute 'hash' cannot be used with 'password-encoder' and " +
                            "will be ignored.", parserContext.extractSource(elt));
                }
                PasswordEncoderParser pep = new PasswordEncoderParser(passwordEncoderElement, parserContext);
                authenticatorBuilder.addPropertyValue("passwordEncoder", pep.getPasswordEncoder());
                
                if (pep.getSaltSource() != null) {
                    parserContext.getReaderContext().warning("Salt source information isn't valid when used with LDAP", 
                    		passwordEncoderElement);
                }
            } else if (StringUtils.hasText(hash)) {
                Class encoderClass = (Class) PasswordEncoderParser.ENCODER_CLASSES.get(hash);
                authenticatorBuilder.addPropertyValue("passwordEncoder", new RootBeanDefinition(encoderClass));
            }
        }
        
        authenticatorBuilder.addConstructorArg(contextSource);
        authenticatorBuilder.addPropertyValue("userDnPatterns", userDnPatternArray);
        
        if (searchBean != null) {
        	authenticatorBuilder.addPropertyValue("userSearch", searchBean);
        }
                
        BeanDefinitionBuilder ldapProvider = BeanDefinitionBuilder.rootBeanDefinition(PROVIDER_CLASS);
        ldapProvider.addConstructorArg(authenticatorBuilder.getBeanDefinition());
        ldapProvider.addConstructorArg(LdapUserServiceBeanDefinitionParser.parseAuthoritiesPopulator(elt, parserContext));
        ldapProvider.addPropertyValue("userDetailsContextMapper", 
        		LdapUserServiceBeanDefinitionParser.parseUserDetailsClass(elt, parserContext));
        parserContext.getRegistry().registerBeanDefinition(BeanIds.LDAP_AUTHENTICATION_PROVIDER, ldapProvider.getBeanDefinition());
        
        ConfigUtils.addAuthenticationProvider(parserContext, BeanIds.LDAP_AUTHENTICATION_PROVIDER);

        return null;
    }
}
