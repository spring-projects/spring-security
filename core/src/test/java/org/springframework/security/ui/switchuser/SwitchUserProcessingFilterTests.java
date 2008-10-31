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

package org.springframework.security.ui.switchuser;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.AccountExpiredException;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.CredentialsExpiredException;
import org.springframework.security.DisabledException;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.security.userdetails.User;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.userdetails.UserDetailsService;
import org.springframework.security.userdetails.UsernameNotFoundException;
import org.springframework.security.util.FieldUtils;
import org.springframework.security.util.MockFilterChain;


/**
 * Tests {@link org.springframework.security.ui.switchuser.SwitchUserProcessingFilter}.
 *
 * @author Mark St.Godard
 * @author Luke Taylor
 * @version $Id$
 */
public class SwitchUserProcessingFilterTests {

    @Before
    public void authenticateCurrentUser() {
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("dano", "hawaii50");
        SecurityContextHolder.getContext().setAuthentication(auth);
    }

    @After
    public void clearContext() {
        SecurityContextHolder.clearContext();
    }

    private MockHttpServletRequest createMockSwitchRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("localhost");
        request.setRequestURI("/j_spring_security_switch_user");

        return request;
    }

    private Authentication switchToUser(String name) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter(SwitchUserProcessingFilter.SPRING_SECURITY_SWITCH_USERNAME_KEY, name);

        SwitchUserProcessingFilter filter = new SwitchUserProcessingFilter();
        filter.setUserDetailsService(new MockUserDetailsService());

        return filter.attemptSwitchUser(request);

    }

    @Test
    public void requiresExitUserMatchesCorrectly() {
        SwitchUserProcessingFilter filter = new SwitchUserProcessingFilter();
        filter.setExitUserUrl("/j_spring_security_my_exit_user");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/j_spring_security_my_exit_user");

        assertTrue(filter.requiresExitUser(request));
    }

    @Test
    public void requiresSwitchMatchesCorrectly() {
        SwitchUserProcessingFilter filter = new SwitchUserProcessingFilter();
        filter.setSwitchUserUrl("/j_spring_security_my_switch_user");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/j_spring_security_my_switch_user");

        assertTrue(filter.requiresSwitchUser(request));
    }

    @Test(expected=UsernameNotFoundException.class)
    public void attemptSwitchToUnknownUserFails() throws Exception {

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter(SwitchUserProcessingFilter.SPRING_SECURITY_SWITCH_USERNAME_KEY, "user-that-doesnt-exist");

        SwitchUserProcessingFilter filter = new SwitchUserProcessingFilter();
        filter.setUserDetailsService(new MockUserDetailsService());
        filter.attemptSwitchUser(request);
    }

    @Test(expected=DisabledException.class)
    public void attemptSwitchToUserThatIsDisabledFails() throws Exception {
        switchToUser("mcgarrett");
    }

    @Test(expected=AccountExpiredException.class)
    public void attemptSwitchToUserWithAccountExpiredFails() throws Exception {
        switchToUser("wofat");
    }

    @Test(expected=CredentialsExpiredException.class)
    public void attemptSwitchToUserWithExpiredCredentialsFails() throws Exception {
        switchToUser("steve");
    }

    @Test(expected=UsernameNotFoundException.class)
    public void switchUserWithNullUsernameThrowsException() throws Exception {
        switchToUser(null);
    }

    @Test
    public void attemptSwitchUserIsSuccessfulWithValidUser() throws Exception {
        assertNotNull(switchToUser("jacklord"));
    }

    @Test
    public void switchToLockedAccountCausesRedirectToSwitchFailureUrl() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/j_spring_security_switch_user");
        request.addParameter(SwitchUserProcessingFilter.SPRING_SECURITY_SWITCH_USERNAME_KEY, "mcgarrett");
        MockHttpServletResponse response = new MockHttpServletResponse();
        SwitchUserProcessingFilter filter = new SwitchUserProcessingFilter();
        filter.setUserDetailsService(new MockUserDetailsService());

        // Check it with no url set (should get a text response)
        filter.doFilterHttp(request, response, new MockFilterChain(false));

        assertEquals("Switch user failed: User is disabled", response.getContentAsString());

        // Now check for the redirect
        request.setContextPath("/mywebapp");
        request.setRequestURI("/mywebapp/j_spring_security_switch_user");
        filter.setSwitchFailureUrl("/switchfailed");
        response = new MockHttpServletResponse();

        filter.doFilterHttp(request, response, new MockFilterChain(true));

        assertEquals("/mywebapp/switchfailed", response.getRedirectedUrl());
        assertEquals("/switchfailed", FieldUtils.getFieldValue(filter, "switchFailureUrl"));
    }

    @Test(expected=IllegalArgumentException.class)
    public void configMissingUserDetailsServiceFails() throws Exception {
        SwitchUserProcessingFilter filter = new SwitchUserProcessingFilter();
        filter.setSwitchUserUrl("/j_spring_security_switch_user");
        filter.setExitUserUrl("/j_spring_security_exit_user");
        filter.setTargetUrl("/main.jsp");
        filter.afterPropertiesSet();
    }

    @Test(expected=IllegalArgumentException.class)
    public void testBadConfigMissingTargetUrl() throws Exception {
        SwitchUserProcessingFilter filter = new SwitchUserProcessingFilter();
        filter.setUserDetailsService(new MockUserDetailsService());
        filter.setSwitchUserUrl("/j_spring_security_switch_user");
        filter.setExitUserUrl("/j_spring_security_exit_user");
        filter.afterPropertiesSet();
    }

    @Test
    public void defaultProcessesFilterUrlMatchesUrlWithPathParameter() {
        MockHttpServletRequest request = createMockSwitchRequest();
        SwitchUserProcessingFilter filter = new SwitchUserProcessingFilter();
        filter.setSwitchUserUrl("/j_spring_security_switch_user");

        request.setRequestURI("/webapp/j_spring_security_switch_user;jsessionid=8JHDUD723J8");
        assertTrue(filter.requiresSwitchUser(request));
    }

    @Test
    public void exitUserJackLordToDanoSucceeds() throws Exception {
        // original user
        GrantedAuthority[] auths = {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")};
        UsernamePasswordAuthenticationToken source = new UsernamePasswordAuthenticationToken("dano", "hawaii50", auths);

        // set current user (Admin)
        GrantedAuthority[] adminAuths = {
                new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO"),
                new SwitchUserGrantedAuthority("PREVIOUS_ADMINISTRATOR", source)
            };
        UsernamePasswordAuthenticationToken admin = new UsernamePasswordAuthenticationToken("jacklord", "hawaii50",
                adminAuths);

        SecurityContextHolder.getContext().setAuthentication(admin);

        MockHttpServletRequest request = createMockSwitchRequest();
        request.setRequestURI("/j_spring_security_exit_user");

        // setup filter
        SwitchUserProcessingFilter filter = new SwitchUserProcessingFilter();
        filter.setUserDetailsService(new MockUserDetailsService());
        filter.setExitUserUrl("/j_spring_security_exit_user");
        filter.setTargetUrl("/webapp/someOtherUrl");

        // run 'exit'
        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain(false));

        // check current user, should be back to original user (dano)
        Authentication targetAuth = SecurityContextHolder.getContext().getAuthentication();
        assertNotNull(targetAuth);
        assertEquals("dano", targetAuth.getPrincipal());
    }

    @Test(expected=AuthenticationException.class)
    public void exitUserWithNoCurrentUserFails() throws Exception {
        // no current user in secure context
        SecurityContextHolder.clearContext();

        MockHttpServletRequest request = createMockSwitchRequest();
        request.setRequestURI("/j_spring_security_exit_user");

        // setup filter
        SwitchUserProcessingFilter filter = new SwitchUserProcessingFilter();
        filter.setUserDetailsService(new MockUserDetailsService());
        filter.setExitUserUrl("/j_spring_security_exit_user");

        // run 'exit', expect fail due to no current user
        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain(false));
    }

    @Test
    public void redirectToTargetUrlIsCorrect() throws Exception {
        MockHttpServletRequest request = createMockSwitchRequest();
        request.setContextPath("/webapp");
        request.addParameter(SwitchUserProcessingFilter.SPRING_SECURITY_SWITCH_USERNAME_KEY, "jacklord");
        request.setRequestURI("/webapp/j_spring_security_switch_user");

        MockHttpServletResponse response = new MockHttpServletResponse();

        SwitchUserProcessingFilter filter = new SwitchUserProcessingFilter();
        filter.setSwitchUserUrl("/j_spring_security_switch_user");
        filter.setTargetUrl("/someOtherUrl");
        filter.setUserDetailsService(new MockUserDetailsService());

        filter.doFilter(request, response, new MockFilterChain(false));

        assertEquals("/webapp/someOtherUrl", response.getRedirectedUrl());
    }

    @Test
    public void redirectOmitsContextPathIfUseRelativeContextSet() throws Exception {
        // set current user
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("dano", "hawaii50");
        SecurityContextHolder.getContext().setAuthentication(auth);

        MockHttpServletRequest request = createMockSwitchRequest();
        request.setContextPath("/webapp");
        request.addParameter(SwitchUserProcessingFilter.SPRING_SECURITY_SWITCH_USERNAME_KEY, "jacklord");
        request.setRequestURI("/webapp/j_spring_security_switch_user");

        MockHttpServletResponse response = new MockHttpServletResponse();

        SwitchUserProcessingFilter filter = new SwitchUserProcessingFilter();
        filter.setSwitchUserUrl("/j_spring_security_switch_user");
        filter.setTargetUrl("/someOtherUrl");
        filter.setUserDetailsService(new MockUserDetailsService());
        filter.setUseRelativeContext(true);

        filter.doFilter(request, response, new MockFilterChain(false));

        assertEquals("/someOtherUrl", response.getRedirectedUrl());
    }

    @Test
    public void testSwitchRequestFromDanoToJackLord() throws Exception {
        // set current user
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("dano", "hawaii50");
        SecurityContextHolder.getContext().setAuthentication(auth);

        // http request
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/webapp/j_spring_security_switch_user");
        request.addParameter(SwitchUserProcessingFilter.SPRING_SECURITY_SWITCH_USERNAME_KEY, "jacklord");

        // http response
        MockHttpServletResponse response = new MockHttpServletResponse();

        // setup filter
        SwitchUserProcessingFilter filter = new SwitchUserProcessingFilter();
        filter.setUserDetailsService(new MockUserDetailsService());
        filter.setSwitchUserUrl("/j_spring_security_switch_user");
        filter.setTargetUrl("/webapp/someOtherUrl");

        MockFilterChain chain = new MockFilterChain(true);

        // test updates user token and context
        filter.doFilter(request, response, chain);

        // check current user
        Authentication targetAuth = SecurityContextHolder.getContext().getAuthentication();
        assertNotNull(targetAuth);
        assertTrue(targetAuth.getPrincipal() instanceof UserDetails);
        assertEquals("jacklord", ((User) targetAuth.getPrincipal()).getUsername());
    }

    @Test
    public void modificationOfAuthoritiesWorks() {
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("dano", "hawaii50");
        SecurityContextHolder.getContext().setAuthentication(auth);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter(SwitchUserProcessingFilter.SPRING_SECURITY_SWITCH_USERNAME_KEY, "jacklord");

        SwitchUserProcessingFilter filter = new SwitchUserProcessingFilter();
        filter.setUserDetailsService(new MockUserDetailsService());
        filter.setSwitchUserAuthorityChanger(new SwitchUserAuthorityChanger() {
            public List modifyGrantedAuthorities(UserDetails targetUser, Authentication currentAuthentication, List authoritiesToBeGranted) {
                List auths = new ArrayList();
                auths.add(new GrantedAuthorityImpl("ROLE_NEW"));
                return auths;
            }
        });

        Authentication result = filter.attemptSwitchUser(request);
        assertTrue(result != null);
        assertEquals(2, result.getAuthorities().size());
        assertEquals("ROLE_NEW", result.getAuthorities().get(0).getAuthority());
    }


    //~ Inner Classes ==================================================================================================

    private class MockUserDetailsService implements UserDetailsService {
        private String password = "hawaii50";

        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
            // jacklord, dano  (active)
            // mcgarrett (disabled)
            // wofat (account expired)
            // steve (credentials expired)
            if ("jacklord".equals(username) || "dano".equals(username)) {
                return new User(username, password, true, true, true, true,
                    new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")});
            } else if ("mcgarrett".equals(username)) {
                return new User(username, password, false, true, true, true,
                    new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")});
            } else if ("wofat".equals(username)) {
                return new User(username, password, true, false, true, true,
                    new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")});
            } else if ("steve".equals(username)) {
                return new User(username, password, true, true, false, true,
                    new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")});
            } else {
                throw new UsernameNotFoundException("Could not find: " + username);
            }
        }

        public void setPassword(String password) {
            this.password = password;
        }
    }
}
