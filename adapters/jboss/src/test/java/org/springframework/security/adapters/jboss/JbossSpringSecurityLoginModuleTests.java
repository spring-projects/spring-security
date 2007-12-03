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

package org.springframework.security.adapters.jboss;

import junit.framework.TestCase;

import org.springframework.security.adapters.PrincipalSpringSecurityUserToken;

import org.jboss.security.SimplePrincipal;

import java.io.IOException;

import java.security.Principal;
import java.security.acl.Group;

import java.util.Properties;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;


/**
 * Tests {@link JbossSpringSecurityLoginModule}.
 *
 * @author Ben Alex
 * @version $Id:JbossSpringSecurityLoginModuleTests.java 2151 2007-09-22 11:54:13Z luke_t $
 */
public class JbossSpringSecurityLoginModuleTests extends TestCase {
    //~ Instance fields ================================================================================================

    private final String ADAPTER_KEY = "my_key";

    //~ Constructors ===================================================================================================

    public JbossSpringSecurityLoginModuleTests() {
        super();
    }

    public JbossSpringSecurityLoginModuleTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(JbossSpringSecurityLoginModuleTests.class);
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testAdapterAbortsIfAppContextDoesNotContainAnAuthenticationBean()
        throws Exception {
        JbossSpringSecurityLoginModule adapter = new JbossSpringSecurityLoginModule();
        Properties props = new Properties();
        props.put("key", ADAPTER_KEY);
        props.put("appContextLocation", "org/springframework/security/adapters/adaptertest-invalid.xml");

        try {
            adapter.initialize(null, null, null, props);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testAdapterAbortsIfNoAppContextSpecified()
        throws Exception {
        JbossSpringSecurityLoginModule adapter = new JbossSpringSecurityLoginModule();

        Properties props = new Properties();
        props.put("key", ADAPTER_KEY);

        try {
            adapter.initialize(null, null, null, props);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("appContextLocation must be defined", expected.getMessage());
        }

        props = new Properties();
        props.put("key", ADAPTER_KEY);
        props.put("appContextLocation", "");

        try {
            adapter.initialize(null, null, null, props);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("appContextLocation must be defined", expected.getMessage());
        }
    }

    public void testAdapterAbortsIfNoKeySpecified() throws Exception {
        JbossSpringSecurityLoginModule adapter = new JbossSpringSecurityLoginModule();

        Properties props = new Properties();
        props.put("appContextLocation", "org/springframework/security/adapters/adaptertest-valid.xml");

        try {
            adapter.initialize(null, null, null, props);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("key must be defined", expected.getMessage());
        }

        props = new Properties();
        props.put("key", "");
        props.put("appContextLocation", "org/springframework/security/adapters/adaptertest-valid.xml");

        try {
            adapter.initialize(null, null, null, props);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("key must be defined", expected.getMessage());
        }
    }

    public void testAdapterAbortsWithIncorrectApplicationContextLocation()
        throws Exception {
        JbossSpringSecurityLoginModule adapter = new JbossSpringSecurityLoginModule();

        Properties props = new Properties();
        props.put("key", ADAPTER_KEY);
        props.put("appContextLocation", "INVALID_PATH");

        try {
            adapter.initialize(null, null, null, props);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue("Cannot locate INVALID_PATH".equals(expected.getMessage()));
        }
    }

    public void testAdapterFailsToAuthenticateIfNoCallbackHandlerAvailable()
        throws Exception {
        JbossSpringSecurityLoginModule adapter = new JbossSpringSecurityLoginModule();
        Properties props = new Properties();
        props.put("key", ADAPTER_KEY);
        props.put("appContextLocation", "org/springframework/security/adapters/adaptertest-valid.xml");

        Subject subject = new Subject();

        adapter.initialize(subject, null, null, props);

        try {
            adapter.login();
        } catch (LoginException loginException) {
            assertEquals("Error: no CallbackHandler available to collect authentication information",
                loginException.getMessage());
        }
    }

    public void testAdapterStartsUpSuccess() throws Exception {
        JbossSpringSecurityLoginModule adapter = new JbossSpringSecurityLoginModule();
        Properties props = new Properties();
        props.put("key", ADAPTER_KEY);
        props.put("appContextLocation", "org/springframework/security/adapters/adaptertest-valid.xml");
        adapter.initialize(null, null, null, props);
        assertTrue(true);
    }

    public void testAuthenticationFailsForIncorrectPassword()
        throws Exception {
        JbossSpringSecurityLoginModule adapter = new JbossSpringSecurityLoginModule();
        Properties props = new Properties();
        props.put("key", ADAPTER_KEY);
        props.put("appContextLocation", "org/springframework/security/adapters/adaptertest-valid.xml");

        Subject subject = new Subject();
        CallbackHandler callback = new MockCallbackHandler("rod", "kangaroo");

        adapter.initialize(subject, callback, null, props);

        try {
            adapter.login();
            fail("Should have thrown FailedLoginException");
        } catch (FailedLoginException expected) {
            assertTrue(true);
        }
    }

    public void testAuthenticationFailsForIncorrectUserName()
        throws Exception {
        JbossSpringSecurityLoginModule adapter = new JbossSpringSecurityLoginModule();
        Properties props = new Properties();
        props.put("key", ADAPTER_KEY);
        props.put("appContextLocation", "org/springframework/security/adapters/adaptertest-valid.xml");

        Subject subject = new Subject();
        CallbackHandler callback = new MockCallbackHandler("melissa", "koala");

        adapter.initialize(subject, callback, null, props);

        try {
            adapter.login();
            fail("Should have thrown FailedLoginException");
        } catch (FailedLoginException expected) {
            assertTrue(true);
        }
    }

    public void testAuthenticationSuccess() throws Exception {
        JbossSpringSecurityLoginModule adapter = new JbossSpringSecurityLoginModule();
        Properties props = new Properties();
        props.put("key", ADAPTER_KEY);
        props.put("appContextLocation", "org/springframework/security/adapters/adaptertest-valid.xml");

        Subject subject = new Subject();
        CallbackHandler callback = new MockCallbackHandler("rod", "koala");

        adapter.initialize(subject, callback, null, props);
        assertTrue(adapter.login());

        Principal result = adapter.getIdentity();

        if (!(result instanceof PrincipalSpringSecurityUserToken)) {
            fail("Should have returned PrincipalSpringSecurityUserToken");
        }

        PrincipalSpringSecurityUserToken castResult = (PrincipalSpringSecurityUserToken) result;
        assertEquals("rod", castResult.getPrincipal());
        assertEquals("koala", castResult.getCredentials());
        assertEquals("ROLE_TELLER", castResult.getAuthorities()[0].getAuthority());
        assertEquals("ROLE_SUPERVISOR", castResult.getAuthorities()[1].getAuthority());
        assertEquals(ADAPTER_KEY.hashCode(), castResult.getKeyHash());
    }

    public void testAuthenticationWithNullPasswordHandledGracefully()
        throws Exception {
        JbossSpringSecurityLoginModule adapter = new JbossSpringSecurityLoginModule();
        Properties props = new Properties();
        props.put("key", ADAPTER_KEY);
        props.put("appContextLocation", "org/springframework/security/adapters/adaptertest-valid.xml");

        Subject subject = new Subject();
        CallbackHandler callback = new MockCallbackHandler("rod", null);

        adapter.initialize(subject, callback, null, props);

        try {
            adapter.login();
            fail("Should have thrown FailedLoginException");
        } catch (FailedLoginException expected) {
            assertTrue(true);
        }
    }

    public void testAuthenticationWithNullUserNameAndNullPasswordHandledGracefully()
        throws Exception {
        JbossSpringSecurityLoginModule adapter = new JbossSpringSecurityLoginModule();
        Properties props = new Properties();
        props.put("key", ADAPTER_KEY);
        props.put("appContextLocation", "org/springframework/security/adapters/adaptertest-valid.xml");

        Subject subject = new Subject();
        CallbackHandler callback = new MockCallbackHandler(null, null);

        adapter.initialize(subject, callback, null, props);

        try {
            adapter.login();
            fail("Should have thrown FailedLoginException");
        } catch (FailedLoginException expected) {
            assertTrue(true);
        }
    }

    public void testAuthenticationWithNullUserNameHandledGracefully()
        throws Exception {
        JbossSpringSecurityLoginModule adapter = new JbossSpringSecurityLoginModule();
        Properties props = new Properties();
        props.put("key", ADAPTER_KEY);
        props.put("appContextLocation", "org/springframework/security/adapters/adaptertest-valid.xml");

        Subject subject = new Subject();
        CallbackHandler callback = new MockCallbackHandler(null, "kangaroo");

        adapter.initialize(subject, callback, null, props);

        try {
            adapter.login();
            fail("Should have thrown FailedLoginException");
        } catch (FailedLoginException expected) {
            assertTrue(true);
        }
    }

    public void testGetRoleSets() throws Exception {
        JbossSpringSecurityLoginModule adapter = new JbossSpringSecurityLoginModule();
        Properties props = new Properties();
        props.put("key", ADAPTER_KEY);
        props.put("appContextLocation", "org/springframework/security/adapters/adaptertest-valid.xml");

        Subject subject = new Subject();
        CallbackHandler callback = new MockCallbackHandler("rod", "koala");

        adapter.initialize(subject, callback, null, props);
        assertTrue(adapter.login());

        Group[] result = adapter.getRoleSets();
        // Expect Roles group.
        assertEquals(1, result.length);

        Group roles = result[0];
        assertTrue(roles.isMember(new SimplePrincipal("ROLE_TELLER")));
        assertTrue(roles.isMember(new SimplePrincipal("ROLE_SUPERVISOR")));
    }

    //~ Inner Classes ==================================================================================================

    private class MockCallbackHandler implements CallbackHandler {
        private String password;
        private String username;

        public MockCallbackHandler(String username, String password) {
            this.username = username;
            this.password = password;
        }

        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for (int i = 0; i < callbacks.length; i++) {
                if (callbacks[i] instanceof NameCallback) {
                    ((NameCallback) callbacks[i]).setName(username);
                } else if (callbacks[i] instanceof PasswordCallback) {
                    if (this.password == null) {
                        ((PasswordCallback) callbacks[i]).setPassword(null);
                    } else {
                        ((PasswordCallback) callbacks[i]).setPassword(password.toCharArray());
                    }
                } else {
                    throw new UnsupportedCallbackException(callbacks[i]);
                }
            }
        }
    }
}
