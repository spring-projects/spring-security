package org.springframework.security.config;

import org.springframework.beans.factory.parsing.BeanDefinitionParsingException;
import org.springframework.security.providers.ProviderManager;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.security.providers.ldap.LdapAuthenticationProvider;
import org.springframework.security.Authentication;
import org.springframework.security.util.InMemoryXmlApplicationContext;
import org.springframework.security.userdetails.ldap.LdapUserDetailsImpl;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.After;


/**
 * @author Luke Taylor
 * @version $Id$
 */
public class LdapProviderBeanDefinitionParserTests {
    InMemoryXmlApplicationContext appCtx;

    @After
    public void closeAppContext() {
        if (appCtx != null) {
            appCtx.close();
            appCtx = null;
        }
    }

    @Test
    public void simpleProviderAuthenticatesCorrectly() {
        setContext("<ldap-server /> <ldap-authentication-provider group-search-filter='member={0}' />");

        LdapAuthenticationProvider provider = getProvider();
        Authentication auth = provider.authenticate(new UsernamePasswordAuthenticationToken("ben", "benspassword"));
        LdapUserDetailsImpl ben = (LdapUserDetailsImpl) auth.getPrincipal();

        assertEquals(2, ben.getAuthorities().length);
    }  
    
    @Test(expected = SecurityConfigurationException.class)
    public void missingServerEltCausesConfigException() {
        setContext("<ldap-authentication-provider />");
    }
    
    @Test
    public void supportsPasswordComparisonAuthentication() {
        setContext("<ldap-server /> " +
        		"<ldap-authentication-provider user-dn-pattern='uid={0},ou=people'>" +
        		"    <password-compare password-attribute='uid'>" +
        		"        <password-encoder hash='plaintext'/>" +
        		"    </password-compare>" +
        		"</ldap-authentication-provider>");
        LdapAuthenticationProvider provider = getProvider();
        provider.authenticate(new UsernamePasswordAuthenticationToken("ben", "ben"));        
    }

    private void setContext(String context) {
        appCtx = new InMemoryXmlApplicationContext(context);
    }    


    private LdapAuthenticationProvider getProvider() {
        ProviderManager authManager = (ProviderManager) appCtx.getBean(BeanIds.AUTHENTICATION_MANAGER);

        assertEquals(1, authManager.getProviders().size());

        LdapAuthenticationProvider provider = (LdapAuthenticationProvider) authManager.getProviders().get(0);
        return provider;
    }    
}
