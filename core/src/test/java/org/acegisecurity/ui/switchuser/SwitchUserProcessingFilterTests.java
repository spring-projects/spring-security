/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

package org.acegisecurity.ui.switchuser;

import junit.framework.TestCase;
import org.acegisecurity.AccountExpiredException;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.CredentialsExpiredException;
import org.acegisecurity.DisabledException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.User;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.acegisecurity.util.MockFilterChain;

import org.springframework.context.support.StaticMessageSource;
import org.springframework.dao.DataAccessException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;


/**
 * Tests {@link org.acegisecurity.ui.switchuser.SwitchUserProcessingFilter}.
 *
 * @author Mark St.Godard
 * @version $Id$
 */
public class SwitchUserProcessingFilterTests extends TestCase {
    //~ Constructors ===========================================================

    public SwitchUserProcessingFilterTests() {
        super();
    }

    public SwitchUserProcessingFilterTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(SwitchUserProcessingFilterTests.class);
    }

    public void testAttemptSwitchToUnknownUser() throws Exception {
        // set current user 
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("dano",
                "hawaii50");
        SecurityContextHolder.getContext().setAuthentication(auth);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter(SwitchUserProcessingFilter.ACEGI_SECURITY_SWITCH_USERNAME_KEY,
            "user-that-doesnt-exist");

        SwitchUserProcessingFilter filter = new SwitchUserProcessingFilter();
        filter.setMessageSource(new StaticMessageSource());
        filter.setAuthenticationDao(new MockAuthenticationDaoUserJackLord());

        try {
            Authentication result = filter.attemptSwitchUser(request);

            fail("Should not be able to switch to unknown user");
        } catch (UsernameNotFoundException expected) {}
    }

    public void testAttemptSwitchToUserThatIsDisabled()
        throws Exception {
        // set current user 
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("dano",
                "hawaii50");
        SecurityContextHolder.getContext().setAuthentication(auth);

        MockHttpServletRequest request = new MockHttpServletRequest();

        // this user is disabled
        request.addParameter(SwitchUserProcessingFilter.ACEGI_SECURITY_SWITCH_USERNAME_KEY,
            "mcgarrett");

        SwitchUserProcessingFilter filter = new SwitchUserProcessingFilter();
        filter.setMessageSource(new StaticMessageSource());
        filter.setAuthenticationDao(new MockAuthenticationDaoUserJackLord());

        try {
            Authentication result = filter.attemptSwitchUser(request);

            fail("Should not be able to switch to disabled user");
        } catch (DisabledException expected) {
            // user should be disabled
        }
    }

    public void testAttemptSwitchToUserWithAccountExpired()
        throws Exception {
        // set current user 
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("dano",
                "hawaii50");
        SecurityContextHolder.getContext().setAuthentication(auth);

        MockHttpServletRequest request = new MockHttpServletRequest();

        // this user is disabled
        request.addParameter(SwitchUserProcessingFilter.ACEGI_SECURITY_SWITCH_USERNAME_KEY,
            "wofat");

        SwitchUserProcessingFilter filter = new SwitchUserProcessingFilter();
        filter.setMessageSource(new StaticMessageSource());
        filter.setAuthenticationDao(new MockAuthenticationDaoUserJackLord());

        try {
            Authentication result = filter.attemptSwitchUser(request);

            fail("Should not be able to switch to user with expired account");
        } catch (AccountExpiredException expected) {
            // expected user account expired
        }
    }

    public void testAttemptSwitchToUserWithExpiredCredentials()
        throws Exception {
        // set current user 
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("dano",
                "hawaii50");
        SecurityContextHolder.getContext().setAuthentication(auth);

        MockHttpServletRequest request = new MockHttpServletRequest();

        // this user is disabled
        request.addParameter(SwitchUserProcessingFilter.ACEGI_SECURITY_SWITCH_USERNAME_KEY,
            "steve");

        SwitchUserProcessingFilter filter = new SwitchUserProcessingFilter();
        filter.setMessageSource(new StaticMessageSource());
        filter.setAuthenticationDao(new MockAuthenticationDaoUserJackLord());

        try {
            Authentication result = filter.attemptSwitchUser(request);

            fail("Should not be able to switch to user with expired account");
        } catch (CredentialsExpiredException expected) {
            // user credentials expired
        }
    }

    public void testAttemptSwitchUser() throws Exception {
        // set current user 
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("dano",
                "hawaii50");
        SecurityContextHolder.getContext().setAuthentication(auth);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter(SwitchUserProcessingFilter.ACEGI_SECURITY_SWITCH_USERNAME_KEY,
            "jacklord");

        SwitchUserProcessingFilter filter = new SwitchUserProcessingFilter();
        filter.setMessageSource(new StaticMessageSource());
        filter.setAuthenticationDao(new MockAuthenticationDaoUserJackLord());

        Authentication result = filter.attemptSwitchUser(request);
        assertTrue(result != null);
    }

    public void testBadConfigMissingAuthenticationDao() {
        SwitchUserProcessingFilter filter = new SwitchUserProcessingFilter();
        filter.setMessageSource(new StaticMessageSource());
        filter.setSwitchUserUrl("/j_acegi_switch_user");
        filter.setExitUserUrl("/j_acegi_exit_user");
        filter.setTargetUrl("/main.jsp");

        try {
            filter.afterPropertiesSet();
            fail("Expect to fail due to missing 'authenticationDao'");
        } catch (Exception expected) {
            // expected exception
        }
    }

    public void testBadConfigMissingTargetUrl() {
        SwitchUserProcessingFilter filter = new SwitchUserProcessingFilter();
        filter.setMessageSource(new StaticMessageSource());
        filter.setAuthenticationDao(new MockAuthenticationDaoUserJackLord());
        filter.setSwitchUserUrl("/j_acegi_switch_user");
        filter.setExitUserUrl("/j_acegi_exit_user");

        try {
            filter.afterPropertiesSet();
            fail("Expect to fail due to missing 'targetUrl'");
        } catch (Exception expected) {
            // expected exception
        }
    }

    public void testDefaultProcessesFilterUrlWithPathParameter() {
        MockHttpServletRequest request = createMockSwitchRequest();
        SwitchUserProcessingFilter filter = new SwitchUserProcessingFilter();
        filter.setMessageSource(new StaticMessageSource());
        filter.setSwitchUserUrl("/j_acegi_switch_user");

        request.setRequestURI(
            "/webapp/j_acegi_switch_user;jsessionid=8JHDUD723J8");
        assertTrue(filter.requiresSwitchUser(request));
    }

    public void testExitRequestUserJackLordToDano() throws Exception {
        // original user	
        GrantedAuthority[] auths = {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                    "ROLE_TWO")};
        UsernamePasswordAuthenticationToken source = new UsernamePasswordAuthenticationToken("dano",
                "hawaii50", auths);

        // set current user (Admin)
        GrantedAuthority[] adminAuths = {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                    "ROLE_TWO"), new SwitchUserGrantedAuthority("PREVIOUS_ADMINISTRATOR",
                    source)};
        UsernamePasswordAuthenticationToken admin = new UsernamePasswordAuthenticationToken("jacklord",
                "hawaii50", adminAuths);

        SecurityContextHolder.getContext().setAuthentication(admin);

        // http request
        MockHttpServletRequest request = createMockSwitchRequest();
        request.setRequestURI("/j_acegi_exit_user");

        // http response
        MockHttpServletResponse response = new MockHttpServletResponse();

        // setup filter
        SwitchUserProcessingFilter filter = new SwitchUserProcessingFilter();
        filter.setMessageSource(new StaticMessageSource());
        filter.setAuthenticationDao(new MockAuthenticationDaoUserJackLord());
        filter.setExitUserUrl("/j_acegi_exit_user");

        MockFilterChain chain = new MockFilterChain(true);

        // run 'exit'
        filter.doFilter(request, response, chain);

        // check current user, should be back to original user (dano) 
        Authentication targetAuth = SecurityContextHolder.getContext()
                                                         .getAuthentication();
        assertNotNull(targetAuth);
        assertEquals("dano", targetAuth.getPrincipal());
    }

    public void testExitUserWithNoCurrentUser() throws Exception {
        // no current user in secure context
        SecurityContextHolder.getContext().setAuthentication(null);

        // http request
        MockHttpServletRequest request = createMockSwitchRequest();
        request.setRequestURI("/j_acegi_exit_user");

        // http response
        MockHttpServletResponse response = new MockHttpServletResponse();

        // setup filter
        SwitchUserProcessingFilter filter = new SwitchUserProcessingFilter();
        filter.setMessageSource(new StaticMessageSource());
        filter.setAuthenticationDao(new MockAuthenticationDaoUserJackLord());
        filter.setExitUserUrl("/j_acegi_exit_user");

        MockFilterChain chain = new MockFilterChain(true);

        // run 'exit', expect fail due to no current user 
        try {
            filter.doFilter(request, response, chain);

            fail("Cannot exit from a user with no current user set!");
        } catch (AuthenticationException expected) {}
    }

    public void testRedirectToTargetUrl() throws Exception {
        // set current user 
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("dano",
                "hawaii50");
        SecurityContextHolder.getContext().setAuthentication(auth);

        MockHttpServletRequest request = createMockSwitchRequest();
        request.addParameter(SwitchUserProcessingFilter.ACEGI_SECURITY_SWITCH_USERNAME_KEY,
            "jacklord");
        request.setRequestURI("/webapp/j_acegi_switch_user");

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain(true);

        SwitchUserProcessingFilter filter = new SwitchUserProcessingFilter();
        filter.setMessageSource(new StaticMessageSource());
        filter.setSwitchUserUrl("/j_acegi_switch_user");
        filter.setTargetUrl("/webapp/someOtherUrl");
        filter.setAuthenticationDao(new MockAuthenticationDaoUserJackLord());

        filter.doFilter(request, response, chain);

        assertEquals("/webapp/someOtherUrl", response.getRedirectedUrl());
    }

    public void testRequiresExitUser() {
        // filter
        SwitchUserProcessingFilter filter = new SwitchUserProcessingFilter();
        filter.setExitUserUrl("/j_acegi_exit_user");

        // request
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/j_acegi_exit_user");

        assertTrue(filter.requiresExitUser(request));
    }

    public void testRequiresSwitch() {
        // filter
        SwitchUserProcessingFilter filter = new SwitchUserProcessingFilter();
        filter.setSwitchUserUrl("/j_acegi_switch_user");

        // request
        MockHttpServletRequest request = createMockSwitchRequest();

        assertTrue(filter.requiresSwitchUser(request));
    }

    public void testSwitchRequestFromDanoToJackLord() throws Exception {
        // set current user 
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("dano",
                "hawaii50");
        SecurityContextHolder.getContext().setAuthentication(auth);

        // http request
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/webapp/j_acegi_switch_user");
        request.addParameter(SwitchUserProcessingFilter.ACEGI_SECURITY_SWITCH_USERNAME_KEY,
            "jacklord");

        // http response
        MockHttpServletResponse response = new MockHttpServletResponse();

        // setup filter
        SwitchUserProcessingFilter filter = new SwitchUserProcessingFilter();
        filter.setMessageSource(new StaticMessageSource());
        filter.setAuthenticationDao(new MockAuthenticationDaoUserJackLord());
        filter.setSwitchUserUrl("/j_acegi_switch_user");

        MockFilterChain chain = new MockFilterChain(true);

        // test updates user token and context
        filter.doFilter(request, response, chain);

        // check current user
        Authentication targetAuth = SecurityContextHolder.getContext()
                                                         .getAuthentication();
        assertNotNull(targetAuth);
        assertTrue(targetAuth.getPrincipal() instanceof UserDetails);
        assertEquals("jacklord", ((User)targetAuth.getPrincipal()).getUsername());        
    }

    private MockHttpServletRequest createMockSwitchRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("localhost");
        request.setRequestURI("/j_acegi_switch_user");

        return request;
    }

    //~ Inner Classes ==========================================================

    private class MockAuthenticationDaoUserJackLord implements UserDetailsService {
        private String password = "hawaii50";

        public void setPassword(String password) {
            this.password = password;
        }

        public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException, DataAccessException {
            // jacklord, dano  (active)
            // mcgarrett (disabled)
            // wofat (account expired)
            // steve (credentials expired)
            if ("jacklord".equals(username) || "dano".equals(username)) {
                return new User(username, password, true, true, true, true,
                    new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                            "ROLE_TWO")});
            } else if ("mcgarrett".equals(username)) {
                return new User(username, password, false, true, true, true,
                    new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                            "ROLE_TWO")});
            } else if ("wofat".equals(username)) {
                return new User(username, password, true, false, true, true,
                    new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                            "ROLE_TWO")});
            } else if ("steve".equals(username)) {
                return new User(username, password, true, true, false, true,
                    new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                            "ROLE_TWO")});
            } else {
                throw new UsernameNotFoundException("Could not find: "
                    + username);
            }
        }
    }
}
