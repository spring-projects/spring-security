/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.authentication.jaas;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.net.URL;
import java.security.Security;
import java.util.*;

import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.junit.Before;
import org.junit.Test;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.core.io.FileSystemResource;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.session.SessionDestroyedEvent;


/**
 * Tests for the JaasAuthenticationProvider
 *
 * @author Ray Krueger
 */
public class JaasAuthenticationProviderTests {
    //~ Instance fields ================================================================================================

    private ApplicationContext context;
    private JaasAuthenticationProvider jaasProvider;
    private JaasEventCheck eventCheck;

    //~ Methods ========================================================================================================

    @Before
    public void setUp() throws Exception {
        String resName = "/" + getClass().getName().replace('.', '/') + ".xml";
        context = new ClassPathXmlApplicationContext(resName);
        eventCheck = (JaasEventCheck) context.getBean("eventCheck");
        jaasProvider = (JaasAuthenticationProvider) context.getBean("jaasAuthenticationProvider");
    }

    @Test
    public void testBadPassword() {
        try {
            jaasProvider.authenticate(new UsernamePasswordAuthenticationToken("user", "asdf"));
            fail("LoginException should have been thrown for the bad password");
        } catch (AuthenticationException e) {}

        assertNotNull("Failure event not fired", eventCheck.failedEvent);
        assertNotNull("Failure event exception was null", eventCheck.failedEvent.getException());
        assertNull("Success event was fired", eventCheck.successEvent);
    }

    @Test
    public void testBadUser() {
        try {
            jaasProvider.authenticate(new UsernamePasswordAuthenticationToken("asdf", "password"));
            fail("LoginException should have been thrown for the bad user");
        } catch (AuthenticationException e) {}

        assertNotNull("Failure event not fired", eventCheck.failedEvent);
        assertNotNull("Failure event exception was null", eventCheck.failedEvent.getException());
        assertNull("Success event was fired", eventCheck.successEvent);
    }

    @Test
    public void testConfigurationLoop() throws Exception {
        String resName = "/" + getClass().getName().replace('.', '/') + ".conf";
        URL url = getClass().getResource(resName);

        Security.setProperty("login.config.url.1", url.toString());

        setUp();
        testFull();
    }

    @Test
    public void detectsMissingLoginConfig() throws Exception {
        JaasAuthenticationProvider myJaasProvider = new JaasAuthenticationProvider();
        myJaasProvider.setApplicationEventPublisher(context);
        myJaasProvider.setAuthorityGranters(jaasProvider.getAuthorityGranters());
        myJaasProvider.setCallbackHandlers(jaasProvider.getCallbackHandlers());
        myJaasProvider.setLoginContextName(jaasProvider.getLoginContextName());

        try {
            myJaasProvider.afterPropertiesSet();
            fail("Should have thrown ApplicationContextException");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().startsWith("loginConfig must be set on"));
        }
    }

    // SEC-1239
    @Test
    public void spacesInLoginConfigPathAreAccepted() throws Exception {
        File configFile;
        // Create temp directory with a space in the name
        File configDir = new File(System.getProperty("java.io.tmpdir") + File.separator + "jaas test");
        configDir.deleteOnExit();

        if (configDir.exists()) {
            configDir.delete();
        }
        configDir.mkdir();
        configFile = File.createTempFile("login", "conf", configDir);
        configFile.deleteOnExit();
        FileOutputStream fos = new FileOutputStream(configFile);
        PrintWriter pw = new PrintWriter(fos);
        pw.append("JAASTestBlah {" +
                    "org.springframework.security.authentication.jaas.TestLoginModule required;" +
                 "};");
        pw.flush();
        pw.close();

        JaasAuthenticationProvider myJaasProvider = new JaasAuthenticationProvider();
        myJaasProvider.setApplicationEventPublisher(context);
        myJaasProvider.setLoginConfig(new FileSystemResource(configFile));
        myJaasProvider.setAuthorityGranters(jaasProvider.getAuthorityGranters());
        myJaasProvider.setCallbackHandlers(jaasProvider.getCallbackHandlers());
        myJaasProvider.setLoginContextName(jaasProvider.getLoginContextName());

        myJaasProvider.afterPropertiesSet();
    }

    @Test
    public void detectsMissingLoginContextName() throws Exception {
        JaasAuthenticationProvider myJaasProvider = new JaasAuthenticationProvider();
        myJaasProvider.setApplicationEventPublisher(context);
        myJaasProvider.setAuthorityGranters(jaasProvider.getAuthorityGranters());
        myJaasProvider.setCallbackHandlers(jaasProvider.getCallbackHandlers());
        myJaasProvider.setLoginConfig(jaasProvider.getLoginConfig());
        myJaasProvider.setLoginContextName(null);

        try {
            myJaasProvider.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().startsWith("loginContextName must be set on"));
        }

        myJaasProvider.setLoginContextName("");

        try {
            myJaasProvider.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().startsWith("loginContextName must be set on"));
        }
    }

    @Test
    public void testFull() throws Exception {
        List<GrantedAuthority> defaultAuths = AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO");
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("user", "password",
                defaultAuths);

        assertTrue(jaasProvider.supports(UsernamePasswordAuthenticationToken.class));

        Authentication auth = jaasProvider.authenticate(token);

        assertNotNull(jaasProvider.getAuthorityGranters());
        assertNotNull(jaasProvider.getCallbackHandlers());
        assertNotNull(jaasProvider.getLoginConfig());
        assertNotNull(jaasProvider.getLoginContextName());

        Collection<? extends GrantedAuthority> list = auth.getAuthorities();
        Set<String> set = AuthorityUtils.authorityListToSet(list);

        assertTrue("GrantedAuthorities should contain ROLE_1", set.contains("ROLE_ONE"));
        assertTrue("GrantedAuthorities should contain ROLE_2", set.contains("ROLE_TWO"));
        assertTrue("GrantedAuthorities should contain ROLE_TEST1", set.contains("ROLE_TEST1"));
        assertTrue("GrantedAuthorities should contain ROLE_TEST2", set.contains("ROLE_TEST2"));

        boolean foundit = false;

        for (GrantedAuthority a : list) {
            if (a instanceof JaasGrantedAuthority) {
                JaasGrantedAuthority grant = (JaasGrantedAuthority) a;
                assertNotNull("Principal was null on JaasGrantedAuthority", grant.getPrincipal());
                foundit = true;
            }
        }

        assertTrue("Could not find a JaasGrantedAuthority", foundit);

        assertNotNull("Success event should be fired", eventCheck.successEvent);
        assertEquals("Auth objects should be equal", auth, eventCheck.successEvent.getAuthentication());
        assertNull("Failure event should not be fired", eventCheck.failedEvent);
    }

    @Test
    public void testGetApplicationEventPublisher() throws Exception {
        assertNotNull(jaasProvider.getApplicationEventPublisher());
    }

    @Test
    public void testLoginExceptionResolver() {
        assertNotNull(jaasProvider.getLoginExceptionResolver());
        jaasProvider.setLoginExceptionResolver(new LoginExceptionResolver() {
                public AuthenticationException resolveException(LoginException e) {
                    return new LockedException("This is just a test!");
                }
            });

        try {
            jaasProvider.authenticate(new UsernamePasswordAuthenticationToken("user", "password"));
        } catch (LockedException e) {}
        catch (Exception e) {
            fail("LockedException should have been thrown and caught");
        }
    }

    @Test
    public void testLogout() throws Exception {
        MockLoginContext loginContext = new MockLoginContext(jaasProvider.getLoginContextName());

        JaasAuthenticationToken token = new JaasAuthenticationToken(null, null, loginContext);

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(token);

        SessionDestroyedEvent event = mock(SessionDestroyedEvent.class);
        when(event.getSecurityContexts()).thenReturn(Arrays.asList(context));

        jaasProvider.handleLogout(event);

        assertTrue(loginContext.loggedOut);
    }

    @Test
    public void testNullDefaultAuthorities() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("user", "password");

        assertTrue(jaasProvider.supports(UsernamePasswordAuthenticationToken.class));

        Authentication auth = jaasProvider.authenticate(token);
        assertTrue("Only ROLE_TEST1 and ROLE_TEST2 should have been returned", auth.getAuthorities().size() == 2);
    }

    @Test
    public void testUnsupportedAuthenticationObjectReturnsNull() {
        assertNull(jaasProvider.authenticate(new TestingAuthenticationToken("foo", "bar", AuthorityUtils.NO_AUTHORITIES )));
    }

    //~ Inner Classes ==================================================================================================

    private static class MockLoginContext extends LoginContext {
        boolean loggedOut = false;

        public MockLoginContext(String loginModule) throws LoginException {
            super(loginModule);
        }

        public void logout() throws LoginException {
            this.loggedOut = true;
        }
    }
}
