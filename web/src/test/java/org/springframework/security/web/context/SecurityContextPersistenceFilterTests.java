package org.springframework.security.web.context;

import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.junit.After;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;

public class SecurityContextPersistenceFilterTests {
    TestingAuthenticationToken testToken = new TestingAuthenticationToken("someone", "passwd", "ROLE_A");

    @After
    public void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void contextIsClearedAfterChainProceeds() throws Exception {
        final FilterChain chain = mock(FilterChain.class);
        final MockHttpServletRequest request = new MockHttpServletRequest();
        final MockHttpServletResponse response = new MockHttpServletResponse();
        SecurityContextPersistenceFilter filter = new SecurityContextPersistenceFilter();
        SecurityContextHolder.getContext().setAuthentication(testToken);

        filter.doFilter(request, response, chain);
        verify(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void contextIsStillClearedIfExceptionIsThrowByFilterChain() throws Exception {
        final FilterChain chain = mock(FilterChain.class);
        final MockHttpServletRequest request = new MockHttpServletRequest();
        final MockHttpServletResponse response = new MockHttpServletResponse();
        SecurityContextPersistenceFilter filter = new SecurityContextPersistenceFilter();
        SecurityContextHolder.getContext().setAuthentication(testToken);
        doThrow(new IOException()).when(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
        try {
            filter.doFilter(request, response, chain);
            fail();
        } catch(IOException expected) {
        }

        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void loadedContextContextIsCopiedToSecurityContextHolderAndUpdatedContextIsStored() throws Exception {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        final MockHttpServletResponse response = new MockHttpServletResponse();
        SecurityContextPersistenceFilter filter = new SecurityContextPersistenceFilter();
        final TestingAuthenticationToken beforeAuth = new TestingAuthenticationToken("someoneelse", "passwd", "ROLE_B");
        final SecurityContext scBefore = new SecurityContextImpl();
        final SecurityContext scExpectedAfter = new SecurityContextImpl();
        scExpectedAfter.setAuthentication(testToken);
        scBefore.setAuthentication(beforeAuth);
        final SecurityContextRepository repo = mock(SecurityContextRepository.class);
        filter.setSecurityContextRepository(repo);

        when(repo.loadContext(any(HttpRequestResponseHolder.class))).thenReturn(scBefore);

        final FilterChain chain = new FilterChain() {
            public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
                assertEquals(beforeAuth, SecurityContextHolder.getContext().getAuthentication());
                // Change the context here
                SecurityContextHolder.setContext(scExpectedAfter);
            }
        };

        filter.doFilter(request, response, chain);

        verify(repo).saveContext(scExpectedAfter, request, response);
    }

    @Test
    public void filterIsNotAppliedAgainIfFilterAppliedAttributeIsSet() throws Exception {
        final FilterChain chain = mock(FilterChain.class);
        final MockHttpServletRequest request = new MockHttpServletRequest();
        final MockHttpServletResponse response = new MockHttpServletResponse();
        SecurityContextPersistenceFilter filter = new SecurityContextPersistenceFilter();
        filter.setSecurityContextRepository(mock(SecurityContextRepository.class));

        request.setAttribute(SecurityContextPersistenceFilter.FILTER_APPLIED, Boolean.TRUE);
        filter.doFilter(request, response, chain);
        verify(chain).doFilter(request, response);
    }

    @Test
    public void sessionIsEagerlyCreatedWhenConfigured() throws Exception {
        final FilterChain chain = mock(FilterChain.class);
        final MockHttpServletRequest request = new MockHttpServletRequest();
        final MockHttpServletResponse response = new MockHttpServletResponse();
        SecurityContextPersistenceFilter filter = new SecurityContextPersistenceFilter();
        filter.setForceEagerSessionCreation(true);
        filter.doFilter(request, response, chain);
        assertNotNull(request.getSession(false));
    }

    @Test
    public void nullSecurityContextRepoDoesntSaveContextOrCreateSession() throws Exception {
        final FilterChain chain = mock(FilterChain.class);
        final MockHttpServletRequest request = new MockHttpServletRequest();
        final MockHttpServletResponse response = new MockHttpServletResponse();
        SecurityContextPersistenceFilter filter = new SecurityContextPersistenceFilter();
        SecurityContextRepository repo = new NullSecurityContextRepository();
        filter.setSecurityContextRepository(repo);
        filter.doFilter(request, response, chain);
        assertFalse(repo.containsContext(request));
        assertNull(request.getSession(false));
    }
}
