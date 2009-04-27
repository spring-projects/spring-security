package org.springframework.security.web.authentication.preauth.websphere;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.After;
import org.junit.Test;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;

/**
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
public class WebSphere2SpringSecurityPropagationInterceptorTests {

    @After
    public void clearContext() {
        SecurityContextHolder.clearContext();
    }

    /** SEC-1078 */
    @Test
    public void createdAuthenticationTokenIsAcceptableToPreauthProvider () throws Throwable {
        WASUsernameAndGroupsExtractor helper = mock(WASUsernameAndGroupsExtractor.class);
        when(helper.getCurrentUserName()).thenReturn("joe");
        WebSphere2SpringSecurityPropagationInterceptor interceptor =
            new WebSphere2SpringSecurityPropagationInterceptor(helper);

        final SecurityContext context = new SecurityContextImpl();

        interceptor.setAuthenticationManager(new AuthenticationManager() {
            public Authentication authenticate(Authentication authentication) {
                // Store the auth object
                context.setAuthentication(authentication);
                return null;
            }
        });
        interceptor.setAuthenticationDetailsSource(mock(AuthenticationDetailsSource.class));
        interceptor.invoke(mock(MethodInvocation.class));

        PreAuthenticatedAuthenticationProvider provider = new PreAuthenticatedAuthenticationProvider();
        AuthenticationUserDetailsService uds = mock(AuthenticationUserDetailsService.class);
        UserDetails user = mock(UserDetails.class);
        when(user.getAuthorities()).thenReturn(AuthorityUtils.createAuthorityList("SOME_ROLE"));
        when(uds.loadUserDetails(any(Authentication.class))).thenReturn(user);
        provider.setPreAuthenticatedUserDetailsService(uds);
        provider.setUserDetailsChecker(mock(UserDetailsChecker.class));

        assertNotNull(provider.authenticate(context.getAuthentication()));
    }

}
