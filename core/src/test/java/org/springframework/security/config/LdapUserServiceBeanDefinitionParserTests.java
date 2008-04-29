package org.springframework.security.config;

import java.util.Set;

import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.util.AuthorityUtils;
import org.springframework.security.util.InMemoryXmlApplicationContext;
import org.springframework.security.userdetails.UserDetailsService;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.userdetails.ldap.InetOrgPerson;
import org.springframework.security.userdetails.ldap.Person;

import org.junit.Test;
import org.junit.After;
import static org.junit.Assert.*;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class LdapUserServiceBeanDefinitionParserTests {
    private InMemoryXmlApplicationContext appCtx;

    @After
    public void closeAppContext() {
        if (appCtx != null) {
            appCtx.close();
            appCtx = null;
        }
    }

    @Test
    public void minimalConfigurationIsParsedOk() throws Exception {
        setContext("<ldap-user-service user-search-filter='(uid={0})' /><ldap-server url='ldap://127.0.0.1:343/dc=springframework,dc=org' />");
    }

    @Test
    public void userServiceReturnsExpectedData() throws Exception {
        setContext("<ldap-user-service id='ldapUDS' user-search-filter='(uid={0})' group-search-filter='member={0}' /><ldap-server />");

        UserDetailsService uds = (UserDetailsService) appCtx.getBean("ldapUDS");
        UserDetails ben = uds.loadUserByUsername("ben");

        Set authorities = AuthorityUtils.authorityArrayToSet(ben.getAuthorities());
        assertEquals(2, authorities.size());
        assertTrue(authorities.contains("ROLE_DEVELOPERS"));
    }

    @Test
    public void differentUserSearchBaseWorksAsExpected() throws Exception {
        setContext("<ldap-user-service id='ldapUDS' " +
                "       user-search-base='ou=otherpeople' " +
                "       user-search-filter='(cn={0})' " +
                "       group-search-filter='member={0}' /><ldap-server />");

        UserDetailsService uds = (UserDetailsService) appCtx.getBean("ldapUDS");
        UserDetails joe = uds.loadUserByUsername("Joe Smeth");

        assertEquals("Joe Smeth", joe.getUsername());
    }

    @Test
    public void rolePrefixIsSupported() throws Exception {
        setContext(
                "<ldap-user-service id='ldapUDS' " +
                "     user-search-filter='(uid={0})' " +
                "     group-search-filter='member={0}' role-prefix='PREFIX_'/>" +
                "<ldap-user-service id='ldapUDSNoPrefix' " +
        		"     user-search-filter='(uid={0})' " +
        		"     group-search-filter='member={0}' role-prefix='none'/><ldap-server />");

        UserDetailsService uds = (UserDetailsService) appCtx.getBean("ldapUDS");
        UserDetails ben = uds.loadUserByUsername("ben");
        assertTrue(AuthorityUtils.authorityArrayToSet(ben.getAuthorities()).contains("PREFIX_DEVELOPERS"));
        
        uds = (UserDetailsService) appCtx.getBean("ldapUDSNoPrefix");
        ben = uds.loadUserByUsername("ben");
        assertTrue(AuthorityUtils.authorityArrayToSet(ben.getAuthorities()).contains("DEVELOPERS"));        
    }
    
    
    
    @Test
    public void differentGroupRoleAttributeWorksAsExpected() throws Exception {
        setContext("<ldap-user-service id='ldapUDS' user-search-filter='(uid={0})' group-role-attribute='ou' group-search-filter='member={0}' /><ldap-server />");

        UserDetailsService uds = (UserDetailsService) appCtx.getBean("ldapUDS");
        UserDetails ben = uds.loadUserByUsername("ben");

        Set authorities = AuthorityUtils.authorityArrayToSet(ben.getAuthorities());
        assertEquals(2, authorities.size());
        assertTrue(authorities.contains(new GrantedAuthorityImpl("ROLE_DEVELOPER")));
        
    }
        
    @Test
    public void isSupportedByAuthenticationProviderElement() {
        setContext(
                "<ldap-server url='ldap://127.0.0.1:343/dc=springframework,dc=org'/>" +
                "<authentication-provider>" +
                "    <ldap-user-service user-search-filter='(uid={0})' />" +
                "</authentication-provider>");
    }
    
    @Test
    public void personContextMapperIsSupported() {
        setContext(
                "<ldap-server />" +
                "<ldap-user-service id='ldapUDS' user-search-filter='(uid={0})' user-details-class='person'/>");
        UserDetailsService uds = (UserDetailsService) appCtx.getBean("ldapUDS");
        UserDetails ben = uds.loadUserByUsername("ben");
        assertTrue(ben instanceof Person);
    }
    
    @Test
    public void inetOrgContextMapperIsSupported() {
        setContext(
                "<ldap-server id='someServer'/>" +
                "<ldap-user-service id='ldapUDS' user-search-filter='(uid={0})' user-details-class='inetOrgPerson'/>");
        UserDetailsService uds = (UserDetailsService) appCtx.getBean("ldapUDS");
        UserDetails ben = uds.loadUserByUsername("ben");
        assertTrue(ben instanceof InetOrgPerson);
    }
    
    
    private void setContext(String context) {
        appCtx = new InMemoryXmlApplicationContext(context);
    }
}
