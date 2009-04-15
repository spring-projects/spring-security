package org.springframework.security.config;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.springframework.security.config.LdapUserServiceBeanDefinitionParser.*;

import java.util.Set;

import org.junit.After;
import org.junit.Test;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.ldap.populator.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.userdetails.InetOrgPerson;
import org.springframework.security.ldap.userdetails.InetOrgPersonContextMapper;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.security.ldap.userdetails.LdapUserDetailsService;
import org.springframework.security.ldap.userdetails.Person;
import org.springframework.security.ldap.userdetails.PersonContextMapper;
import org.w3c.dom.Element;

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
    public void beanClassNamesAreCorrect() throws Exception {
        assertEquals(LDAP_SEARCH_CLASS, FilterBasedLdapUserSearch.class.getName());
        assertEquals(PERSON_MAPPER_CLASS, PersonContextMapper.class.getName());
        assertEquals(INET_ORG_PERSON_MAPPER_CLASS, InetOrgPersonContextMapper.class.getName());
        assertEquals(LDAP_USER_MAPPER_CLASS, LdapUserDetailsMapper.class.getName());
        assertEquals(LDAP_AUTHORITIES_POPULATOR_CLASS, DefaultLdapAuthoritiesPopulator.class.getName());
        assertEquals(LdapUserDetailsService.class.getName(), new LdapUserServiceBeanDefinitionParser().getBeanClassName(mock(Element.class)));
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

        Set<String> authorities = AuthorityUtils.authorityListToSet(ben.getAuthorities());
        assertEquals(3, authorities.size());
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
        assertTrue(AuthorityUtils.authorityListToSet(ben.getAuthorities()).contains("PREFIX_DEVELOPERS"));

        uds = (UserDetailsService) appCtx.getBean("ldapUDSNoPrefix");
        ben = uds.loadUserByUsername("ben");
        assertTrue(AuthorityUtils.authorityListToSet(ben.getAuthorities()).contains("DEVELOPERS"));
    }



    @Test
    public void differentGroupRoleAttributeWorksAsExpected() throws Exception {
        setContext("<ldap-user-service id='ldapUDS' user-search-filter='(uid={0})' group-role-attribute='ou' group-search-filter='member={0}' /><ldap-server />");

        UserDetailsService uds = (UserDetailsService) appCtx.getBean("ldapUDS");
        UserDetails ben = uds.loadUserByUsername("ben");

        Set<String> authorities = AuthorityUtils.authorityListToSet(ben.getAuthorities());
        assertEquals(3, authorities.size());
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
