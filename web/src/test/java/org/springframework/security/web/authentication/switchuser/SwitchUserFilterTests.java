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

package org.springframework.security.web.authentication.switchuser;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.servlet.FilterChain;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.util.FieldUtils;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.switchuser.SwitchUserAuthorityChanger;
import org.springframework.security.web.authentication.switchuser.SwitchUserGrantedAuthority;
import org.springframework.security.web.authentication.switchuser.SwitchUserFilter;


/**
 * Tests {@link org.springframework.security.web.authentication.switchuser.SwitchUserFilter}.
 *
 * @author Mark St.Godard
 * @author Luke Taylor
 */
public class SwitchUserFilterTests {
    private final static List<GrantedAuthority> ROLES_12 = AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO");

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
        request.addParameter(SwitchUserFilter.SPRING_SECURITY_SWITCH_USERNAME_KEY, name);

        SwitchUserFilter filter = new SwitchUserFilter();
        filter.setUserDetailsService(new MockUserDetailsService());

        return filter.attemptSwitchUser(request);

    }

    @Test
    public void requiresExitUserMatchesCorrectly() {
        SwitchUserFilter filter = new SwitchUserFilter();
        filter.setExitUserUrl("/j_spring_security_my_exit_user");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/j_spring_security_my_exit_user");

        assertTrue(filter.requiresExitUser(request));
    }

    @Test
    public void requiresSwitchMatchesCorrectly() {
        SwitchUserFilter filter = new SwitchUserFilter();
        filter.setSwitchUserUrl("/j_spring_security_my_switch_user");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/j_spring_security_my_switch_user");

        assertTrue(filter.requiresSwitchUser(request));
    }

    @Test(expected=UsernameNotFoundException.class)
    public void attemptSwitchToUnknownUserFails() throws Exception {

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter(SwitchUserFilter.SPRING_SECURITY_SWITCH_USERNAME_KEY, "user-that-doesnt-exist");

        SwitchUserFilter filter = new SwitchUserFilter();
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
        request.addParameter(SwitchUserFilter.SPRING_SECURITY_SWITCH_USERNAME_KEY, "mcgarrett");
        MockHttpServletResponse response = new MockHttpServletResponse();
        SwitchUserFilter filter = new SwitchUserFilter();
        filter.setTargetUrl("/target");
        filter.setUserDetailsService(new MockUserDetailsService());
        filter.afterPropertiesSet();

        // Check it with no url set (should get a text response)
        FilterChain chain = mock(FilterChain.class);
        filter.doFilter(request, response, chain);
        verify(chain, never()).doFilter(request, response);

        assertEquals("Authentication Failed: User is disabled", response.getErrorMessage());

        // Now check for the redirect
        request.setContextPath("/mywebapp");
        request.setRequestURI("/mywebapp/j_spring_security_switch_user");
        filter = new SwitchUserFilter();
        filter.setTargetUrl("/target");
        filter.setUserDetailsService(new MockUserDetailsService());
        filter.setSwitchFailureUrl("/switchfailed");
        filter.afterPropertiesSet();
        response = new MockHttpServletResponse();

        chain = mock(FilterChain.class);
        filter.doFilter(request, response, chain);
        verify(chain, never()).doFilter(request, response);

        assertEquals("/mywebapp/switchfailed", response.getRedirectedUrl());
        assertEquals("/switchfailed", FieldUtils.getFieldValue(filter, "switchFailureUrl"));
    }

    @Test(expected=IllegalArgumentException.class)
    public void configMissingUserDetailsServiceFails() throws Exception {
        SwitchUserFilter filter = new SwitchUserFilter();
        filter.setSwitchUserUrl("/j_spring_security_switch_user");
        filter.setExitUserUrl("/j_spring_security_exit_user");
        filter.setTargetUrl("/main.jsp");
        filter.afterPropertiesSet();
    }

    @Test(expected=IllegalArgumentException.class)
    public void testBadConfigMissingTargetUrl() throws Exception {
        SwitchUserFilter filter = new SwitchUserFilter();
        filter.setUserDetailsService(new MockUserDetailsService());
        filter.setSwitchUserUrl("/j_spring_security_switch_user");
        filter.setExitUserUrl("/j_spring_security_exit_user");
        filter.afterPropertiesSet();
    }

    @Test
    public void defaultProcessesFilterUrlMatchesUrlWithPathParameter() {
        MockHttpServletRequest request = createMockSwitchRequest();
        SwitchUserFilter filter = new SwitchUserFilter();
        filter.setSwitchUserUrl("/j_spring_security_switch_user");

        request.setRequestURI("/webapp/j_spring_security_switch_user;jsessionid=8JHDUD723J8");
        assertTrue(filter.requiresSwitchUser(request));
    }

    @Test
    public void exitUserJackLordToDanoSucceeds() throws Exception {
        // original user
        UsernamePasswordAuthenticationToken source = new UsernamePasswordAuthenticationToken("dano", "hawaii50", ROLES_12);

        // set current user (Admin)
        List<GrantedAuthority> adminAuths = new ArrayList<GrantedAuthority>();
        adminAuths.addAll(ROLES_12);
        adminAuths.add(new SwitchUserGrantedAuthority("PREVIOUS_ADMINISTRATOR", source));
        UsernamePasswordAuthenticationToken admin =
            new UsernamePasswordAuthenticationToken("jacklord", "hawaii50", adminAuths);

        SecurityContextHolder.getContext().setAuthentication(admin);

        MockHttpServletRequest request = createMockSwitchRequest();
        request.setRequestURI("/j_spring_security_exit_user");

        // setup filter
        SwitchUserFilter filter = new SwitchUserFilter();
        filter.setUserDetailsService(new MockUserDetailsService());
        filter.setExitUserUrl("/j_spring_security_exit_user");
        filter.setSuccessHandler(new SimpleUrlAuthenticationSuccessHandler("/webapp/someOtherUrl"));

        // run 'exit'
        FilterChain chain = mock(FilterChain.class);
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, chain);

        verify(chain, never()).doFilter(request, response);

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
        SwitchUserFilter filter = new SwitchUserFilter();
        filter.setUserDetailsService(new MockUserDetailsService());
        filter.setExitUserUrl("/j_spring_security_exit_user");

        // run 'exit', expect fail due to no current user
        FilterChain chain = mock(FilterChain.class);
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, chain);

        verify(chain, never()).doFilter(request, response);
    }

    @Test
    public void redirectToTargetUrlIsCorrect() throws Exception {
        MockHttpServletRequest request = createMockSwitchRequest();
        request.setContextPath("/webapp");
        request.addParameter(SwitchUserFilter.SPRING_SECURITY_SWITCH_USERNAME_KEY, "jacklord");
        request.setRequestURI("/webapp/j_spring_security_switch_user");

        SwitchUserFilter filter = new SwitchUserFilter();
        filter.setSwitchUserUrl("/j_spring_security_switch_user");
        filter.setSuccessHandler(new SimpleUrlAuthenticationSuccessHandler("/someOtherUrl"));
        filter.setUserDetailsService(new MockUserDetailsService());

        FilterChain chain = mock(FilterChain.class);
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, chain);

        verify(chain, never()).doFilter(request, response);


        assertEquals("/webapp/someOtherUrl", response.getRedirectedUrl());
    }

    @Test
    public void redirectOmitsContextPathIfUseRelativeContextSet() throws Exception {
        // set current user
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("dano", "hawaii50");
        SecurityContextHolder.getContext().setAuthentication(auth);

        MockHttpServletRequest request = createMockSwitchRequest();
        request.setContextPath("/webapp");
        request.addParameter(SwitchUserFilter.SPRING_SECURITY_SWITCH_USERNAME_KEY, "jacklord");
        request.setRequestURI("/webapp/j_spring_security_switch_user");

        SwitchUserFilter filter = new SwitchUserFilter();
        filter.setSwitchUserUrl("/j_spring_security_switch_user");
        SimpleUrlAuthenticationSuccessHandler switchSuccessHandler =
            new SimpleUrlAuthenticationSuccessHandler("/someOtherUrl");
        DefaultRedirectStrategy contextRelativeRedirector = new DefaultRedirectStrategy();
        contextRelativeRedirector.setContextRelative(true);
        switchSuccessHandler.setRedirectStrategy(contextRelativeRedirector);
        filter.setSuccessHandler(switchSuccessHandler);
        filter.setUserDetailsService(new MockUserDetailsService());

        FilterChain chain = mock(FilterChain.class);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        verify(chain, never()).doFilter(request, response);


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
        request.addParameter(SwitchUserFilter.SPRING_SECURITY_SWITCH_USERNAME_KEY, "jacklord");

        // http response
        MockHttpServletResponse response = new MockHttpServletResponse();

        // setup filter
        SwitchUserFilter filter = new SwitchUserFilter();
        filter.setUserDetailsService(new MockUserDetailsService());
        filter.setSwitchUserUrl("/j_spring_security_switch_user");
        filter.setSuccessHandler(new SimpleUrlAuthenticationSuccessHandler("/webapp/someOtherUrl"));

        FilterChain chain = mock(FilterChain.class);

        // test updates user token and context
        filter.doFilter(request, response, chain);
        verify(chain, never()).doFilter(request, response);

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
        request.addParameter(SwitchUserFilter.SPRING_SECURITY_SWITCH_USERNAME_KEY, "jacklord");

        SwitchUserFilter filter = new SwitchUserFilter();
        filter.setUserDetailsService(new MockUserDetailsService());
        filter.setSwitchUserAuthorityChanger(new SwitchUserAuthorityChanger() {
            public Collection<GrantedAuthority> modifyGrantedAuthorities(UserDetails targetUser, Authentication currentAuthentication, Collection<? extends GrantedAuthority> authoritiesToBeGranted) {
                List <GrantedAuthority>auths = new ArrayList<GrantedAuthority>();
                auths.add(new GrantedAuthorityImpl("ROLE_NEW"));
                return auths;
            }
        });

        Authentication result = filter.attemptSwitchUser(request);
        assertTrue(result != null);
        assertEquals(2, result.getAuthorities().size());
        assertTrue(AuthorityUtils.authorityListToSet(result.getAuthorities()).contains("ROLE_NEW"));
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
                return new User(username, password, true, true, true, true, ROLES_12);
            } else if ("mcgarrett".equals(username)) {
                return new User(username, password, false, true, true, true, ROLES_12);
            } else if ("wofat".equals(username)) {
                return new User(username, password, true, false, true, true, ROLES_12);
            } else if ("steve".equals(username)) {
                return new User(username, password, true, true, false, true, ROLES_12);
            } else {
                throw new UsernameNotFoundException("Could not find: " + username);
            }
        }
    }
}
