package org.springframework.security.config.authentication;

import static org.junit.Assert.*;

import org.springframework.security.config.util.InMemoryXmlApplicationContext;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.context.support.AbstractXmlApplicationContext;
import org.springframework.beans.FatalBeanException;

import org.junit.Test;
import org.junit.After;

/**
 * @author Luke Taylor
 */
public class UserServiceBeanDefinitionParserTests {
    private AbstractXmlApplicationContext appContext;

    @After
    public void closeAppContext() {
        if (appContext != null) {
            appContext.close();
        }
    }

    @Test
    public void userServiceWithValidPropertiesFileWorksSuccessfully() {
        setContext(
                "<user-service id='service' " +
                        "properties='classpath:org/springframework/security/config/users.properties'/>");
        UserDetailsService userService = (UserDetailsService) appContext.getBean("service");
        userService.loadUserByUsername("bob");
        userService.loadUserByUsername("joe");
    }

    @Test
    public void userServiceWithEmbeddedUsersWorksSuccessfully() {
        setContext(
                "<user-service id='service'>" +
                "    <user name='joe' password='joespassword' authorities='ROLE_A'/>" +
                "</user-service>");
        UserDetailsService userService = (UserDetailsService) appContext.getBean("service");
        userService.loadUserByUsername("joe");
    }

    @Test
    public void namePasswordAndAuthoritiesSupportPlaceholders() {
        System.setProperty("principal.name", "joe");
        System.setProperty("principal.pass", "joespassword");
        System.setProperty("principal.authorities", "ROLE_A,ROLE_B");
        setContext(
                "<b:bean class='org.springframework.beans.factory.config.PropertyPlaceholderConfigurer'/>" +
                "<user-service id='service'>" +
                "    <user name='${principal.name}' password='${principal.pass}' authorities='${principal.authorities}'/>" +
                "</user-service>");
        UserDetailsService userService = (UserDetailsService) appContext.getBean("service");
        UserDetails joe = userService.loadUserByUsername("joe");
        assertEquals("joespassword", joe.getPassword());
        assertEquals(2, joe.getAuthorities().size());
    }

    @Test
    public void embeddedUsersWithNoPasswordIsGivenGeneratedValue() {
        setContext(
                "<user-service id='service'>" +
                "    <user name='joe' authorities='ROLE_A'/>" +
                "</user-service>");
        UserDetailsService userService = (UserDetailsService) appContext.getBean("service");
        UserDetails joe = userService.loadUserByUsername("joe");
        assertTrue(joe.getPassword().length() > 0);
        Long.parseLong(joe.getPassword());
    }

    @Test
    public void disabledAndEmbeddedFlagsAreSupported() {
        setContext(
                "<user-service id='service'>" +
                "    <user name='joe' password='joespassword' authorities='ROLE_A' locked='true'/>" +
                "    <user name='bob' password='bobspassword' authorities='ROLE_A' disabled='true'/>" +
                "</user-service>");
        UserDetailsService userService = (UserDetailsService) appContext.getBean("service");
        UserDetails joe = userService.loadUserByUsername("joe");
        assertFalse(joe.isAccountNonLocked());
        UserDetails bob = userService.loadUserByUsername("bob");
        assertFalse(bob.isEnabled());
    }


    @Test(expected=FatalBeanException.class)
    public void userWithBothPropertiesAndEmbeddedUsersThrowsException() {
        setContext(
                "<user-service id='service' properties='doesntmatter.props'>" +
                "    <user name='joe' password='joespassword' authorities='ROLE_A'/>" +
                "</user-service>");
        UserDetailsService userService = (UserDetailsService) appContext.getBean("service");
        userService.loadUserByUsername("joe");
    }

    @Test(expected= FatalBeanException.class)
    public void multipleTopLevelUseWithoutIdThrowsException() {
        setContext(
                "<user-service properties='classpath:org/springframework/security/config/users.properties'/>" +
                "<user-service properties='classpath:org/springframework/security/config/users.properties'/>");

    }

    @Test(expected= FatalBeanException.class)
    public void userServiceWithMissingPropertiesFileThrowsException() {
        setContext("<user-service id='service' properties='classpath:doesntexist.properties'/>");
    }

    private void setContext(String context) {
        appContext = new InMemoryXmlApplicationContext(context);
    }
}
