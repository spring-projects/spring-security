package org.springframework.security.config;

import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.providers.ldap.LdapAuthenticationProvider;
import org.springframework.security.providers.ldap.authenticator.BindAuthenticator;
import org.springframework.security.providers.ldap.authenticator.PasswordComparisonAuthenticator;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
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
    
    private static final String DEF_USER_SEARCH_FILTER="uid={0}";

    public BeanDefinition parse(Element elt, ParserContext parserContext) {
        RuntimeBeanReference contextSource = LdapUserServiceBeanDefinitionParser.parseServerReference(elt, parserContext);
        
        RootBeanDefinition searchBean = LdapUserServiceBeanDefinitionParser.parseSearchBean(elt, parserContext);
        String userDnPattern = elt.getAttribute(ATT_USER_DN_PATTERN);
        
        String[] userDnPatternArray = new String[0];
        
        if (StringUtils.hasText(userDnPattern)) {
            userDnPatternArray = new String[] {userDnPattern};
            // TODO: Validate the pattern and make sure it is a valid DN.
        } else if (searchBean == null) {
            logger.info("No search information or DN pattern specified. Using default search filter '" + DEF_USER_SEARCH_FILTER + "'");
            searchBean = new RootBeanDefinition(FilterBasedLdapUserSearch.class);
            searchBean.setSource(elt);
            searchBean.getConstructorArgumentValues().addIndexedArgumentValue(0, "");
            searchBean.getConstructorArgumentValues().addIndexedArgumentValue(1, DEF_USER_SEARCH_FILTER);
            searchBean.getConstructorArgumentValues().addIndexedArgumentValue(2, contextSource);
        }
        
        RootBeanDefinition authenticator = new RootBeanDefinition(BindAuthenticator.class);
        Element passwordCompareElt = DomUtils.getChildElementByTagName(elt, Elements.LDAP_PASSWORD_COMPARE);
        
        if (passwordCompareElt != null) {
            authenticator = new RootBeanDefinition(PasswordComparisonAuthenticator.class);
            
            String passwordAttribute = passwordCompareElt.getAttribute(ATT_USER_PASSWORD);
            if (StringUtils.hasText(passwordAttribute)) {
                authenticator.getPropertyValues().addPropertyValue("passwordAttributeName", passwordAttribute);
            }
            
            Element passwordEncoderElement = DomUtils.getChildElementByTagName(passwordCompareElt, Elements.PASSWORD_ENCODER);
            String hash = passwordCompareElt.getAttribute(ATT_HASH);
            
            if (passwordEncoderElement != null) {
                if (StringUtils.hasText(hash)) {
                    parserContext.getReaderContext().warning("Attribute 'hash' cannot be used with 'password-encoder' and " +
                            "will be ignored.", parserContext.extractSource(elt));
                }                
                PasswordEncoderParser pep = new PasswordEncoderParser(passwordEncoderElement, parserContext);
                authenticator.getPropertyValues().addPropertyValue("passwordEncoder", pep.getPasswordEncoder());
                
                if (pep.getSaltSource() != null) {
                    parserContext.getReaderContext().warning("Salt source information isn't valid when used with LDAP", passwordEncoderElement);
                }
            } else if (StringUtils.hasText(hash)) {
                Class encoderClass = (Class) PasswordEncoderParser.ENCODER_CLASSES.get(hash);
                authenticator.getPropertyValues().addPropertyValue("passwordEncoder", new RootBeanDefinition(encoderClass));
            }
        } 
        
        authenticator.getConstructorArgumentValues().addGenericArgumentValue(contextSource);
        authenticator.getPropertyValues().addPropertyValue("userDnPatterns", userDnPatternArray);
        
        if (searchBean != null) {
            authenticator.getPropertyValues().addPropertyValue("userSearch", searchBean);
        }
                
        RootBeanDefinition ldapProvider = new RootBeanDefinition(LdapAuthenticationProvider.class);
        ldapProvider.getConstructorArgumentValues().addGenericArgumentValue(authenticator);
        ldapProvider.getConstructorArgumentValues().addGenericArgumentValue(LdapUserServiceBeanDefinitionParser.parseAuthoritiesPopulator(elt, parserContext));
        ldapProvider.getPropertyValues().addPropertyValue("userDetailsContextMapper", 
        		LdapUserServiceBeanDefinitionParser.parseUserDetailsClass(elt, parserContext));
        
        ConfigUtils.getRegisteredProviders(parserContext).add(ldapProvider);

        return null;
    }
}
