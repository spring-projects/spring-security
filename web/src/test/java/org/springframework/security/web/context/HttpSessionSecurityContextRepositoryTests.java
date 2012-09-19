/*
 * Copyright 2002-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.web.context;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.web.context.HttpSessionSecurityContextRepository.*;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.junit.After;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * @author Luke Taylor
 * @author Rob Winch
 */
public class HttpSessionSecurityContextRepositoryTests {
    private final TestingAuthenticationToken testToken = new TestingAuthenticationToken("someone", "passwd", "ROLE_A");

    @After
    public void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void sessionIsntCreatedIfContextDoesntChange() throws Exception {
        HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository();
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, response);
        SecurityContext context = repo.loadContext(holder);
        assertNull(request.getSession(false));
        repo.saveContext(context, holder.getRequest(), holder.getResponse());
        assertNull(request.getSession(false));
    }

    @Test
    public void sessionIsntCreatedIfAllowSessionCreationIsFalse() throws Exception {
        HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository();
        repo.setAllowSessionCreation(false);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, response);
        SecurityContext context = repo.loadContext(holder);
        // Change context
        context.setAuthentication(testToken);
        repo.saveContext(context, holder.getRequest(), holder.getResponse());
        assertNull(request.getSession(false));
    }

    @Test
    public void existingContextIsSuccessFullyLoadedFromSessionAndSavedBack() throws Exception {
        HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository();
        repo.setSpringSecurityContextKey("imTheContext");
        MockHttpServletRequest request = new MockHttpServletRequest();
        SecurityContextHolder.getContext().setAuthentication(testToken);
        request.getSession().setAttribute("imTheContext", SecurityContextHolder.getContext());
        MockHttpServletResponse response = new MockHttpServletResponse();
        HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, response);
        SecurityContext context = repo.loadContext(holder);
        assertNotNull(context);
        assertEquals(testToken, context.getAuthentication());
        // Won't actually be saved as it hasn't changed, but go through the use case anyway
        repo.saveContext(context, holder.getRequest(), holder.getResponse());
        assertEquals(context, request.getSession().getAttribute("imTheContext"));
    }

    // SEC-1528
    @Test
    public void saveContextCallsSetAttributeIfContextIsModifiedDirectlyDuringRequest() throws Exception {
        HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository();
        MockHttpServletRequest request = new MockHttpServletRequest();
        // Set up an existing authenticated context, mocking that it is in the session already
        SecurityContext ctx = SecurityContextHolder.getContext();
        ctx.setAuthentication(testToken);
        HttpSession session = mock(HttpSession.class);
        when(session.getAttribute(SPRING_SECURITY_CONTEXT_KEY)).thenReturn(ctx);
        request.setSession(session);
        HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, new MockHttpServletResponse());
        assertSame(ctx, repo.loadContext(holder));

        // Modify context contents. Same user, different role
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("someone", "passwd", "ROLE_B"));
        repo.saveContext(ctx, holder.getRequest(), holder.getResponse());

        // Must be called even though the value in the local VM is already the same
        verify(session).setAttribute(SPRING_SECURITY_CONTEXT_KEY, ctx);
    }

    @Test
    public void nonSecurityContextInSessionIsIgnored() throws Exception {
        HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository();
        MockHttpServletRequest request = new MockHttpServletRequest();
        SecurityContextHolder.getContext().setAuthentication(testToken);
        request.getSession().setAttribute(SPRING_SECURITY_CONTEXT_KEY, "NotASecurityContextInstance");
        MockHttpServletResponse response = new MockHttpServletResponse();
        HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, response);
        SecurityContext context = repo.loadContext(holder);
        assertNotNull(context);
        assertNull(context.getAuthentication());
    }

    @Test
    public void sessionIsCreatedAndContextStoredWhenContextChanges() throws Exception {
        HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository();
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, response);
        SecurityContext context = repo.loadContext(holder);
        assertNull(request.getSession(false));
        // Simulate authentication during the request
        context.setAuthentication(testToken);
        repo.saveContext(context, holder.getRequest(), holder.getResponse());
        assertNotNull(request.getSession(false));
        assertEquals(context, request.getSession().getAttribute(SPRING_SECURITY_CONTEXT_KEY));
    }

    @Test
    public void redirectCausesEarlySaveOfContext() throws Exception {
        HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository();
        repo.setSpringSecurityContextKey("imTheContext");
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, response);
        SecurityContextHolder.setContext(repo.loadContext(holder));
        SecurityContextHolder.getContext().setAuthentication(testToken);
        holder.getResponse().sendRedirect("/doesntmatter");
        assertEquals(SecurityContextHolder.getContext(), request.getSession().getAttribute("imTheContext"));
        assertTrue(((SaveContextOnUpdateOrErrorResponseWrapper)holder.getResponse()).isContextSaved());
        repo.saveContext(SecurityContextHolder.getContext(), holder.getRequest(), holder.getResponse());
        // Check it's still the same
        assertEquals(SecurityContextHolder.getContext(), request.getSession().getAttribute("imTheContext"));
    }

    @Test
    public void sendErrorCausesEarlySaveOfContext() throws Exception {
        HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository();
        repo.setSpringSecurityContextKey("imTheContext");
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, response);
        SecurityContextHolder.setContext(repo.loadContext(holder));
        SecurityContextHolder.getContext().setAuthentication(testToken);
        holder.getResponse().sendError(404);
        assertEquals(SecurityContextHolder.getContext(), request.getSession().getAttribute("imTheContext"));
        assertTrue(((SaveContextOnUpdateOrErrorResponseWrapper)holder.getResponse()).isContextSaved());
        repo.saveContext(SecurityContextHolder.getContext(), holder.getRequest(), holder.getResponse());
        // Check it's still the same
        assertEquals(SecurityContextHolder.getContext(), request.getSession().getAttribute("imTheContext"));
    }

    // SEC-2005
    @Test
    public void flushBufferCausesEarlySaveOfContext() throws Exception {
        HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository();
        repo.setSpringSecurityContextKey("imTheContext");
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, response);
        SecurityContextHolder.setContext(repo.loadContext(holder));
        SecurityContextHolder.getContext().setAuthentication(testToken);
        holder.getResponse().flushBuffer();
        assertEquals(SecurityContextHolder.getContext(), request.getSession().getAttribute("imTheContext"));
        assertTrue(((SaveContextOnUpdateOrErrorResponseWrapper)holder.getResponse()).isContextSaved());
        repo.saveContext(SecurityContextHolder.getContext(), holder.getRequest(), holder.getResponse());
        // Check it's still the same
        assertEquals(SecurityContextHolder.getContext(), request.getSession().getAttribute("imTheContext"));
    }

    // SEC-2005
    @Test
    public void writerFlushCausesEarlySaveOfContext() throws Exception {
        HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository();
        repo.setSpringSecurityContextKey("imTheContext");
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, response);
        SecurityContextHolder.setContext(repo.loadContext(holder));
        SecurityContextHolder.getContext().setAuthentication(testToken);
        holder.getResponse().getWriter().flush();
        assertEquals(SecurityContextHolder.getContext(), request.getSession().getAttribute("imTheContext"));
        assertTrue(((SaveContextOnUpdateOrErrorResponseWrapper)holder.getResponse()).isContextSaved());
        repo.saveContext(SecurityContextHolder.getContext(), holder.getRequest(), holder.getResponse());
        // Check it's still the same
        assertEquals(SecurityContextHolder.getContext(), request.getSession().getAttribute("imTheContext"));
    }

    // SEC-2005
    @Test
    public void writerCloseCausesEarlySaveOfContext() throws Exception {
        HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository();
        repo.setSpringSecurityContextKey("imTheContext");
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, response);
        SecurityContextHolder.setContext(repo.loadContext(holder));
        SecurityContextHolder.getContext().setAuthentication(testToken);
        holder.getResponse().getWriter().close();
        assertEquals(SecurityContextHolder.getContext(), request.getSession().getAttribute("imTheContext"));
        assertTrue(((SaveContextOnUpdateOrErrorResponseWrapper)holder.getResponse()).isContextSaved());
        repo.saveContext(SecurityContextHolder.getContext(), holder.getRequest(), holder.getResponse());
        // Check it's still the same
        assertEquals(SecurityContextHolder.getContext(), request.getSession().getAttribute("imTheContext"));
    }

    // SEC-2005
    @Test
    public void outputStreamFlushCausesEarlySaveOfContext() throws Exception {
        HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository();
        repo.setSpringSecurityContextKey("imTheContext");
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, response);
        SecurityContextHolder.setContext(repo.loadContext(holder));
        SecurityContextHolder.getContext().setAuthentication(testToken);
        holder.getResponse().getOutputStream().flush();
        assertEquals(SecurityContextHolder.getContext(), request.getSession().getAttribute("imTheContext"));
        assertTrue(((SaveContextOnUpdateOrErrorResponseWrapper)holder.getResponse()).isContextSaved());
        repo.saveContext(SecurityContextHolder.getContext(), holder.getRequest(), holder.getResponse());
        // Check it's still the same
        assertEquals(SecurityContextHolder.getContext(), request.getSession().getAttribute("imTheContext"));
    }

    // SEC-2005
    @Test
    public void outputStreamCloseCausesEarlySaveOfContext() throws Exception {
        HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository();
        repo.setSpringSecurityContextKey("imTheContext");
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, response);
        SecurityContextHolder.setContext(repo.loadContext(holder));
        SecurityContextHolder.getContext().setAuthentication(testToken);
        holder.getResponse().getOutputStream().close();
        assertEquals(SecurityContextHolder.getContext(), request.getSession().getAttribute("imTheContext"));
        assertTrue(((SaveContextOnUpdateOrErrorResponseWrapper)holder.getResponse()).isContextSaved());
        repo.saveContext(SecurityContextHolder.getContext(), holder.getRequest(), holder.getResponse());
        // Check it's still the same
        assertEquals(SecurityContextHolder.getContext(), request.getSession().getAttribute("imTheContext"));
    }

    // SEC-SEC-2055
    @Test
    public void outputStreamCloseDelegate() throws Exception {
        HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository();
        repo.setSpringSecurityContextKey("imTheContext");
        MockHttpServletRequest request = new MockHttpServletRequest();
        HttpServletResponse response = mock(HttpServletResponse.class);
        ServletOutputStream outputstream = mock(ServletOutputStream.class);
        when(response.getOutputStream()).thenReturn(outputstream);
        HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, response);
        SecurityContextHolder.setContext(repo.loadContext(holder));
        SecurityContextHolder.getContext().setAuthentication(testToken);
        holder.getResponse().getOutputStream().close();
        verify(outputstream).close();
    }

    // SEC-SEC-2055
    @Test
    public void outputStreamFlushesDelegate() throws Exception {
        HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository();
        repo.setSpringSecurityContextKey("imTheContext");
        MockHttpServletRequest request = new MockHttpServletRequest();
        HttpServletResponse response = mock(HttpServletResponse.class);
        ServletOutputStream outputstream = mock(ServletOutputStream.class);
        when(response.getOutputStream()).thenReturn(outputstream);
        HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, response);
        SecurityContextHolder.setContext(repo.loadContext(holder));
        SecurityContextHolder.getContext().setAuthentication(testToken);
        holder.getResponse().getOutputStream().flush();
        verify(outputstream).flush();
    }

    @Test
    public void noSessionIsCreatedIfSessionWasInvalidatedDuringTheRequest() throws Exception {
        HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession();
        MockHttpServletResponse response = new MockHttpServletResponse();
        HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, response);
        SecurityContextHolder.setContext(repo.loadContext(holder));
        SecurityContextHolder.getContext().setAuthentication(testToken);
        request.getSession().invalidate();
        repo.saveContext(SecurityContextHolder.getContext(), holder.getRequest(), holder.getResponse());
        assertNull(request.getSession(false));
    }

    // SEC-1315
    @Test
    public void noSessionIsCreatedIfAnonymousTokenIsUsed() throws Exception {
        HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository();
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, response);
        SecurityContextHolder.setContext(repo.loadContext(holder));
        SecurityContextHolder.getContext().setAuthentication(
                new AnonymousAuthenticationToken("key", "anon", AuthorityUtils.createAuthorityList("ANON")));
        repo.saveContext(SecurityContextHolder.getContext(), holder.getRequest(), holder.getResponse());
        assertNull(request.getSession(false));
    }

    // SEC-1587
    @Test
    public void contextIsRemovedFromSessionIfCurrentContextIsAnonymous() throws Exception {
        HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository();
        MockHttpServletRequest request = new MockHttpServletRequest();
        SecurityContext ctxInSession = SecurityContextHolder.createEmptyContext();
        ctxInSession.setAuthentication(testToken);
        request.getSession().setAttribute(SPRING_SECURITY_CONTEXT_KEY, ctxInSession);
        HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, new MockHttpServletResponse());
        repo.loadContext(holder);
        SecurityContextHolder.getContext().setAuthentication(new AnonymousAuthenticationToken("x","x", testToken.getAuthorities()));
        repo.saveContext(SecurityContextHolder.getContext(), holder.getRequest(), holder.getResponse());
        assertNull(request.getSession().getAttribute(SPRING_SECURITY_CONTEXT_KEY));
    }

    @Test
    public void contextIsRemovedFromSessionIfCurrentContextIsEmpty() throws Exception {
        HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository();
        repo.setSpringSecurityContextKey("imTheContext");
        MockHttpServletRequest request = new MockHttpServletRequest();
        SecurityContext ctxInSession = SecurityContextHolder.createEmptyContext();
        ctxInSession.setAuthentication(testToken);
        request.getSession().setAttribute("imTheContext", ctxInSession);
        HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, new MockHttpServletResponse());
        repo.loadContext(holder);
        // Save an empty context
        repo.saveContext(SecurityContextHolder.getContext(), holder.getRequest(), holder.getResponse());
        assertNull(request.getSession().getAttribute("imTheContext"));
    }

    // SEC-1735
    @Test
    public void contextIsNotRemovedFromSessionIfContextBeforeExecutionDefault() throws Exception {
        HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository();
        MockHttpServletRequest request = new MockHttpServletRequest();
        HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, new MockHttpServletResponse());
        repo.loadContext(holder);
        SecurityContext ctxInSession = SecurityContextHolder.createEmptyContext();
        ctxInSession.setAuthentication(testToken);
        request.getSession().setAttribute(SPRING_SECURITY_CONTEXT_KEY, ctxInSession);
        SecurityContextHolder.getContext().setAuthentication(new AnonymousAuthenticationToken("x","x", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));
        repo.saveContext(SecurityContextHolder.getContext(), holder.getRequest(), holder.getResponse());
        assertSame(ctxInSession,request.getSession().getAttribute(SPRING_SECURITY_CONTEXT_KEY));
    }

    @Test
    @SuppressWarnings("deprecation")
    public void sessionDisableUrlRewritingPreventsSessionIdBeingWrittenToUrl() throws Exception {
        HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository();
        MockHttpServletRequest request = new MockHttpServletRequest();
        final String sessionId = ";jsessionid=id";
        MockHttpServletResponse response = new MockHttpServletResponse() {
            @Override
            public String encodeRedirectUrl(String url) {
                return url + sessionId;
            }

            @Override
            public String encodeRedirectURL(String url) {
                return url + sessionId;
            }

            @Override
            public String encodeUrl(String url) {
                return url + sessionId;
            }

            @Override
            public String encodeURL(String url) {
                return url + sessionId;
            }
        };
        HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, response);
        repo.loadContext(holder);
        String url = "/aUrl";
        assertEquals(url + sessionId, holder.getResponse().encodeRedirectUrl(url));
        assertEquals(url + sessionId, holder.getResponse().encodeRedirectURL(url));
        assertEquals(url + sessionId, holder.getResponse().encodeUrl(url));
        assertEquals(url + sessionId, holder.getResponse().encodeURL(url));
        repo.setDisableUrlRewriting(true);
        holder = new HttpRequestResponseHolder(request, response);
        repo.loadContext(holder);
        assertEquals(url, holder.getResponse().encodeRedirectUrl(url));
        assertEquals(url, holder.getResponse().encodeRedirectURL(url));
        assertEquals(url, holder.getResponse().encodeUrl(url));
        assertEquals(url, holder.getResponse().encodeURL(url));
    }
}
