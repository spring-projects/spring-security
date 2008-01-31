package org.springframework.security.config;

import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.junit.After;

import org.springframework.security.userdetails.jdbc.JdbcUserDetailsManager;
import org.springframework.security.util.InMemoryXmlApplicationContext;
import org.springframework.security.AuthenticationManager;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;

/**
 * @author Ben Alex
 * @author Luke Taylor
 * @version $Id$
 */
public class JdbcUserServiceBeanDefinitionParserTests {
    private InMemoryXmlApplicationContext appContext;

    private static String DATA_SOURCE =
            "    <b:bean id='populator' class='org.springframework.security.config.DataSourcePopulator'>" +
            "        <b:property name='dataSource' ref='dataSource'/>" +
            "    </b:bean>" +
            "    <b:bean id='dataSource' class='org.springframework.jdbc.datasource.DriverManagerDataSource'>" +
            "        <b:property name='driverClassName' value='org.hsqldb.jdbcDriver'/>" +
            "        <b:property name='url' value='jdbc:hsqldb:mem:jdbcnamespaces'/>" +
            "        <b:property name='username' value='sa'/>" +
            "        <b:property name='password' value=''/>" +
            "    </b:bean>";

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
    	assertTrue(mgr.loadUserByUsername("rod") != null);
    }

    @Test
    public void beanIdIsParsedCorrectly() {
        setContext("<jdbc-user-service id='customUserService' data-source-ref='dataSource'/>" + DATA_SOURCE);
        JdbcUserDetailsManager mgr = (JdbcUserDetailsManager) appContext.getBean("customUserService");
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

    private void setContext(String context) {
        appContext = new InMemoryXmlApplicationContext(context);
    }
}
