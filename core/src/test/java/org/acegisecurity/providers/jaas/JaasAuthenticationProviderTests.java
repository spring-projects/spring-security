/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.providers.jaas;

import junit.framework.TestCase;
import net.sf.acegisecurity.*;
import net.sf.acegisecurity.providers.TestingAuthenticationToken;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import javax.security.auth.login.LoginException;
import java.net.URL;
import java.security.Security;
import java.util.Arrays;
import java.util.List;


/**
 * Tests for the JaasAuthenticationProvider
 *
 * @author Ray Krueger
 * @version $Id$
 */
public class JaasAuthenticationProviderTests extends TestCase {
    //~ Instance fields ========================================================

    private ApplicationContext context;
    private JaasAuthenticationProvider jaasProvider;
    private JaasEventCheck eventCheck;

    //~ Methods ================================================================

    public void testBadPassword() {
        try {
            jaasProvider.authenticate(new UsernamePasswordAuthenticationToken("user", "asdf"));
            fail("LoginException should have been thrown for the bad password");
        } catch (AuthenticationException e) {
        }

        assertNotNull("Failure event not fired", eventCheck.failedEvent);
        assertNotNull("Failure event exception was null",
                eventCheck.failedEvent.getException());
        assertNull("Success event was fired", eventCheck.successEvent);
    }

    public void testBadUser() {
        try {
            jaasProvider.authenticate(new UsernamePasswordAuthenticationToken("asdf", "password"));
            fail("LoginException should have been thrown for the bad user");
        } catch (AuthenticationException e) {
        }

        assertNotNull("Failure event not fired", eventCheck.failedEvent);
        assertNotNull("Failure event exception was null",
                eventCheck.failedEvent.getException());
        assertNull("Success event was fired", eventCheck.successEvent);
    }

    public void testConfigurationLoop() throws Exception {
        String resName = "/" + getClass().getName().replace('.', '/') + ".conf";
        URL url = getClass().getResource(resName);

        Security.setProperty("policy.allowSystemProperty", "false");
        Security.setProperty("login.config.url.1", url.toString());

        setUp();
        testFull();
    }

    public void testDetectsMissingLoginConfig() throws Exception {
        JaasAuthenticationProvider myJaasProvider = new JaasAuthenticationProvider();
        myJaasProvider.setApplicationContext(context);
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

    public void testDetectsMissingLoginContextName() throws Exception {
        JaasAuthenticationProvider myJaasProvider = new JaasAuthenticationProvider();
        myJaasProvider.setApplicationContext(context);
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

    public void testFull() throws Exception {
        GrantedAuthorityImpl role1 = new GrantedAuthorityImpl("ROLE_1");
        GrantedAuthorityImpl role2 = new GrantedAuthorityImpl("ROLE_2");

        GrantedAuthority[] defaultAuths = new GrantedAuthority[]{role1, role2, };

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("user",
                "password", defaultAuths);

        assertTrue(jaasProvider.supports(UsernamePasswordAuthenticationToken.class));

        Authentication auth = jaasProvider.authenticate(token);

        assertNotNull(jaasProvider.getAuthorityGranters());
        assertNotNull(jaasProvider.getCallbackHandlers());
        assertNotNull(jaasProvider.getLoginConfig());
        assertNotNull(jaasProvider.getLoginContextName());

        List list = Arrays.asList(auth.getAuthorities());

        assertTrue("GrantedAuthorities does not contain ROLE_TEST",
                list.contains(new GrantedAuthorityImpl("ROLE_TEST")));

        assertTrue("GrantedAuthorities does not contain ROLE_1",
                list.contains(role1));

        assertTrue("GrantedAuthorities does not contain ROLE_2",
                list.contains(role2));

        boolean foundit = false;

        for (int i = 0; i < list.size(); i++) {
            Object obj = list.get(i);

            if (obj instanceof JaasGrantedAuthority) {
                JaasGrantedAuthority grant = (JaasGrantedAuthority) obj;
                assertNotNull("Principal was null on JaasGrantedAuthority",
                        grant.getPrincipal());
                foundit = true;
            }
        }

        assertTrue("Could not find a JaasGrantedAuthority", foundit);

        assertNotNull("Success event not fired", eventCheck.successEvent);
        assertEquals("Auth objects are not equal", auth,
                eventCheck.successEvent.getAuthentication());

        assertNull("Failure event was fired", eventCheck.failedEvent);
    }

    public void testLoginExceptionResolver() {
        assertNotNull(jaasProvider.getLoginExceptionResolver());
        jaasProvider.setLoginExceptionResolver(new LoginExceptionResolver() {
            public AcegiSecurityException resolveException(LoginException e) {
                return new LockedException("This is just a test!");
            }
        });

        try {
            jaasProvider.authenticate(new UsernamePasswordAuthenticationToken("user", "password"));
        } catch (LockedException e) {
        } catch (Exception e) {
            fail("LockedException should have been thrown and caught");
        }
    }

    public void testNullDefaultAuthorities() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("user",
                "password", null);

        assertTrue(jaasProvider.supports(UsernamePasswordAuthenticationToken.class));

        Authentication auth = jaasProvider.authenticate(token);
        assertTrue("Only ROLE_TEST should have been returned",
                auth.getAuthorities().length == 1);
    }

    public void testGetApplicationContext() throws Exception {
        assertNotNull(jaasProvider.getApplicationContext());
    }

    public void testUnsupportedAuthenticationObjectReturnsNull() {
        assertNull(jaasProvider.authenticate(new TestingAuthenticationToken("foo", "bar",
                new GrantedAuthority[]{})));
    }

    protected void setUp() throws Exception {
        String resName = "/" + getClass().getName().replace('.', '/') + ".xml";
        context = new ClassPathXmlApplicationContext(resName);
        eventCheck = (JaasEventCheck) context.getBean("eventCheck");
        jaasProvider = (JaasAuthenticationProvider) context.getBean("jaasAuthenticationProvider");
    }
}
