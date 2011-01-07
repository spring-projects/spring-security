package org.springframework.security.web.authentication.preauth.websphere;

import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.*;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.mapping.SimpleAttributes2GrantedAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.FilterChain;

/**
 * @author Luke Taylor
 */
public class WebSpherePreAuthenticatedProcessingFilterTests {

    @After
    public void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void principalsAndCredentialsAreExtractedCorrectly() throws Exception {
        new WebSpherePreAuthenticatedProcessingFilter();
        WASUsernameAndGroupsExtractor helper = mock(WASUsernameAndGroupsExtractor.class);
        when(helper.getCurrentUserName()).thenReturn("jerry");
        WebSpherePreAuthenticatedProcessingFilter filter = new WebSpherePreAuthenticatedProcessingFilter(helper);
        assertEquals("jerry", filter.getPreAuthenticatedPrincipal(new MockHttpServletRequest()));
        assertEquals("N/A", filter.getPreAuthenticatedCredentials(new MockHttpServletRequest()));

        AuthenticationManager am = mock(AuthenticationManager.class);
        when(am.authenticate(any(Authentication.class))).thenAnswer(new Answer<Authentication>() {
            public Authentication answer(InvocationOnMock invocation) throws Throwable {
                return (Authentication) invocation.getArguments()[0];
            }
        });

        filter.setAuthenticationManager(am);
        WebSpherePreAuthenticatedWebAuthenticationDetailsSource ads =
                new WebSpherePreAuthenticatedWebAuthenticationDetailsSource(helper);
        ads.setWebSphereGroups2GrantedAuthoritiesMapper(new SimpleAttributes2GrantedAuthoritiesMapper());
        filter.setAuthenticationDetailsSource(ads);

        filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), mock(FilterChain.class));
    }


}
