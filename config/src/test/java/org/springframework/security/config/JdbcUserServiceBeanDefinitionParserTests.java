package org.springframework.security.config;

import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Test;
import org.springframework.security.AuthenticationManager;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;
import org.springframework.security.providers.ProviderManager;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.security.providers.dao.DaoAuthenticationProvider;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.userdetails.jdbc.JdbcUserDetailsManager;
import org.springframework.security.util.AuthorityUtils;
import org.springframework.security.util.FieldUtils;

/**
 * @author Ben Alex
 * @author Luke Taylor
 * @version $Id$
 */
public class JdbcUserServiceBeanDefinitionParserTests {
    private static String USER_CACHE_XML = "<b:bean id='userCache' class='org.springframework.security.providers.dao.MockUserCache'/>";

    private static String DATA_SOURCE =
            "    <b:bean id='populator' class='org.springframework.security.config.DataSourcePopulator'>" +
            "        <b:property name='dataSource' ref='dataSource'/>" +
            "    </b:bean>" +

            "    <b:bean id='dataSource' class='org.springframework.security.TestDataSource'>" +
            "        <b:constructor-arg value='jdbcnamespaces'/>" +
            "    </b:bean>";

    private InMemoryXmlApplicationContext appContext;

    @After
    public void closeAppContext() {
        if (appContext != null) {
            appContext.close();
        }
    }

    @Test
    public void validUsernameIsFound() {
        setContext("<jdbc-user-service data-source-ref='dataSource'/>" + DATA_SOURCE);
        JdbcUserDetailsManager mgr = (JdbcUserDetailsManager) appContext.getBean(BeanIds.USER_DETAILS_SERVICE);
        assertNotNull(mgr.loadUserByUsername("rod"));
    }

    @Test
    public void beanIdIsParsedCorrectly() {
        setContext("<jdbc-user-service id='myUserService' data-source-ref='dataSource'/>" + DATA_SOURCE);
        assertTrue(appContext.getBean("myUserService") instanceof JdbcUserDetailsManager);
    }

    @Test
    public void usernameAndAuthorityQueriesAreParsedCorrectly() throws Exception {
        String userQuery = "select username, password, true from users where username = ?";
        String authoritiesQuery = "select username, authority from authorities where username = ? and 1 = 1";
        setContext("<jdbc-user-service id='myUserService' " +
                "data-source-ref='dataSource' " +
                "users-by-username-query='"+ userQuery +"' " +
                "authorities-by-username-query='" + authoritiesQuery + "'/>" + DATA_SOURCE);
        JdbcUserDetailsManager mgr = (JdbcUserDetailsManager) appContext.getBean("myUserService");
        assertEquals(userQuery, FieldUtils.getFieldValue(mgr, "usersByUsernameQuery"));
        assertEquals(authoritiesQuery, FieldUtils.getFieldValue(mgr, "authoritiesByUsernameQuery"));
        assertTrue(mgr.loadUserByUsername("rod") != null);
    }

    @Test
    public void groupQueryIsParsedCorrectly() throws Exception {
        setContext("<jdbc-user-service id='myUserService' " +
                "data-source-ref='dataSource' " +
                "group-authorities-by-username-query='blah blah'/>" + DATA_SOURCE);
        JdbcUserDetailsManager mgr = (JdbcUserDetailsManager) appContext.getBean("myUserService");
        assertEquals("blah blah", FieldUtils.getFieldValue(mgr, "groupAuthoritiesByUsernameQuery"));
        assertTrue((Boolean)FieldUtils.getFieldValue(mgr, "enableGroups"));
    }

    @Test
    public void cacheRefIsparsedCorrectly() {
        setContext("<jdbc-user-service id='myUserService' cache-ref='userCache' data-source-ref='dataSource'/>"
                + DATA_SOURCE +USER_CACHE_XML);
        CachingUserDetailsService cachingUserService =
            (CachingUserDetailsService) appContext.getBean("myUserService" + AbstractUserDetailsServiceBeanDefinitionParser.CACHING_SUFFIX);
        assertSame(cachingUserService.getUserCache(), appContext.getBean("userCache"));
        assertNotNull(cachingUserService.loadUserByUsername("rod"));
        assertNotNull(cachingUserService.loadUserByUsername("rod"));
    }

    @Test
    public void isSupportedByAuthenticationProviderElement() {
        setContext(
                "<authentication-provider>" +
                "    <jdbc-user-service data-source-ref='dataSource'/>" +
                "</authentication-provider>" + DATA_SOURCE);
        AuthenticationManager mgr = (AuthenticationManager) appContext.getBean(BeanIds.AUTHENTICATION_MANAGER);
        mgr.authenticate(new UsernamePasswordAuthenticationToken("rod", "koala"));
    }

    @Test
    public void cacheIsInjectedIntoAuthenticationProvider() {
        setContext(
                "<authentication-provider>" +
                "    <jdbc-user-service cache-ref='userCache' data-source-ref='dataSource'/>" +
                "</authentication-provider>" + DATA_SOURCE + USER_CACHE_XML);
        ProviderManager mgr = (ProviderManager) appContext.getBean(BeanIds.AUTHENTICATION_MANAGER);
        DaoAuthenticationProvider provider = (DaoAuthenticationProvider) mgr.getProviders().get(0);
        assertSame(provider.getUserCache(), appContext.getBean("userCache"));
        provider.authenticate(new UsernamePasswordAuthenticationToken("rod","koala"));
        assertNotNull("Cache should contain user after authentication", provider.getUserCache().getUserFromCache("rod"));
    }

    @Test
    public void rolePrefixIsUsedWhenSet() {
        setContext("<jdbc-user-service id='myUserService' role-prefix='PREFIX_' data-source-ref='dataSource'/>" + DATA_SOURCE);
        JdbcUserDetailsManager mgr = (JdbcUserDetailsManager) appContext.getBean("myUserService");
        UserDetails rod = mgr.loadUserByUsername("rod");
        assertTrue(AuthorityUtils.authorityListToSet(rod.getAuthorities()).contains("PREFIX_ROLE_SUPERVISOR"));
    }


    private void setContext(String context) {
        appContext = new InMemoryXmlApplicationContext(context);
    }
}
