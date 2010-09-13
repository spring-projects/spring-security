/*
 * Copyright 2010 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.web.authentication.jaas;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.IOException;
import java.security.AccessController;
import java.security.Principal;
import java.util.HashMap;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextInputCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.jaas.JaasAuthenticationToken;
import org.springframework.security.authentication.jaas.TestLoginModule;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Tests the JaasApiIntegrationFilter.
 * 
 * @author Rob Winch
 */
public class JaasApiIntegrationFilterTest {
    //~ Instance fields ================================================================================================
    private JaasApiIntegrationFilter filter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private Authentication token;
    private Subject authenticatedSubject;
    private Configuration testConfiguration;
    private CallbackHandler callbackHandler;
    //~ Methods ========================================================================================================

    @Before
    public void onBeforeTests() throws Exception {
        this.filter = new JaasApiIntegrationFilter();
        this.request = new MockHttpServletRequest();
        this.response = new MockHttpServletResponse();

        authenticatedSubject = new Subject();
        authenticatedSubject.getPrincipals().add(new Principal() {
            public String getName() {
                return "principal";
            }
        });
        authenticatedSubject.getPrivateCredentials().add("password");
        authenticatedSubject.getPublicCredentials().add("username");
        callbackHandler = new CallbackHandler() {
            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                for (Callback callback : callbacks) {
                    if (callback instanceof NameCallback) {
                        ((NameCallback) callback).setName("user");
                    } else if (callback instanceof PasswordCallback) {
                        ((PasswordCallback) callback).setPassword("password".toCharArray());
                    } else if (callback instanceof TextInputCallback) {
                        // ignore
                    } else {
                        throw new UnsupportedCallbackException(callback, "Unrecognized Callback " + callback);
                    }
                }
            }
        };
        testConfiguration = new Configuration() {
            public void refresh() {
            }

            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                return new AppConfigurationEntry[] { new AppConfigurationEntry(TestLoginModule.class.getName(),
                        LoginModuleControlFlag.REQUIRED, new HashMap<String, String>()) };
            }
        };
        LoginContext ctx = new LoginContext("SubjectDoAsFilterTest", authenticatedSubject, callbackHandler,
                testConfiguration);
        ctx.login();
        token = new JaasAuthenticationToken("username", "password", AuthorityUtils.createAuthorityList("ROLE_ADMIN"),
                ctx);

        // just in case someone forgot to clear the context
        SecurityContextHolder.clearContext();
    }

    @After
    public void onAfterTests() {
        SecurityContextHolder.clearContext();
    }

    /**
     * Ensure a Subject was not setup in some other manner.
     */
    @Test
    public void currentSubjectNull() {
        assertNull(Subject.getSubject(AccessController.getContext()));
    }

    @Test
    public void obtainSubjectNullAuthentication() {
        assertNullSubject(filter.obtainSubject(request));
    }

    @Test
    public void obtainSubjectNonJaasAuthentication() {
        Authentication authentication = new TestingAuthenticationToken("un", "pwd");
        authentication.setAuthenticated(true);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        assertNullSubject(filter.obtainSubject(request));
    }

    @Test
    public void obtainSubjectNullLoginContext() {
        token = new JaasAuthenticationToken("un", "pwd", AuthorityUtils.createAuthorityList("ROLE_ADMIN"), null);
        SecurityContextHolder.getContext().setAuthentication(token);
        assertNullSubject(filter.obtainSubject(request));
    }

    @Test
    public void obtainSubjectNullSubject() throws Exception {
        LoginContext ctx = new LoginContext("obtainSubjectNullSubject", null, callbackHandler, testConfiguration);
        assertNull(ctx.getSubject());
        token = new JaasAuthenticationToken("un", "pwd", AuthorityUtils.createAuthorityList("ROLE_ADMIN"), ctx);
        SecurityContextHolder.getContext().setAuthentication(token);
        assertNullSubject(filter.obtainSubject(request));
    }

    @Test
    public void obtainSubject() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(token);
        assertEquals(authenticatedSubject, filter.obtainSubject(request));
    }

    @Test
    public void doFilterCurrentSubjectPopulated() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(token);
        assertJaasSubjectEquals(authenticatedSubject);
    }

    @Test
    public void doFilterAuthenticationNotAuthenticated() throws Exception {
        // Authentication is null, so no Subject is populated.
        token.setAuthenticated(false);
        SecurityContextHolder.getContext().setAuthentication(token);
        assertJaasSubjectEquals(null);
        filter.setCreateEmptySubject(true);
        assertJaasSubjectEquals(new Subject());
    }

    @Test
    public void doFilterAuthenticationNull() throws Exception {
        assertJaasSubjectEquals(null);
        filter.setCreateEmptySubject(true);
        assertJaasSubjectEquals(new Subject());
    }

    //~ Helper Methods ====================================================================================================

    private void assertJaasSubjectEquals(final Subject expectedValue) throws Exception {
        MockFilterChain chain = new MockFilterChain() {
            public void doFilter(ServletRequest request, ServletResponse response) {
                // See if the subject was updated
                Subject currentSubject = Subject.getSubject(AccessController.getContext());
                assertEquals(expectedValue, currentSubject);

                // run so we know the chain was executed
                super.doFilter(request, response);
            }
        };
        filter.doFilter(request, response, chain);
        // ensure that the chain was actually invoked
        assertNotNull(chain.getRequest());
    }

    private void assertNullSubject(Subject subject) {
        assertNull("Subject is expected to be null, but is not. Got " + subject, subject);
    }
}