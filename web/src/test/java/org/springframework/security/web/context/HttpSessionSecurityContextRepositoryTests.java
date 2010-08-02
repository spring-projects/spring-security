package org.springframework.security.web.context;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.web.context.HttpSessionSecurityContextRepository.*;

import javax.servlet.http.HttpSession;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

public class HttpSessionSecurityContextRepositoryTests {
    private final TestingAuthenticationToken testToken = new TestingAuthenticationToken("someone", "passwd", "ROLE_A");

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
        MockHttpServletRequest request = new MockHttpServletRequest();
        SecurityContextHolder.getContext().setAuthentication(testToken);
        request.getSession().setAttribute(SPRING_SECURITY_CONTEXT_KEY, SecurityContextHolder.getContext());
        MockHttpServletResponse response = new MockHttpServletResponse();
        HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, response);
        SecurityContext context = repo.loadContext(holder);
        assertNotNull(context);
        assertEquals(testToken, context.getAuthentication());
        // Won't actually be saved as it hasn't changed, but go through the use case anyway
        repo.saveContext(context, holder.getRequest(), holder.getResponse());
        assertEquals(context, request.getSession().getAttribute(SPRING_SECURITY_CONTEXT_KEY));
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
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, response);
        SecurityContextHolder.setContext(repo.loadContext(holder));
        SecurityContextHolder.getContext().setAuthentication(testToken);
        holder.getResponse().sendRedirect("/doesntmatter");
        assertEquals(SecurityContextHolder.getContext(), request.getSession().getAttribute(SPRING_SECURITY_CONTEXT_KEY));
        assertTrue(((SaveContextOnUpdateOrErrorResponseWrapper)holder.getResponse()).isContextSaved());
        repo.saveContext(SecurityContextHolder.getContext(), holder.getRequest(), holder.getResponse());
        // Check it's still the same
        assertEquals(SecurityContextHolder.getContext(), request.getSession().getAttribute(SPRING_SECURITY_CONTEXT_KEY));
    }

    @Test
    public void sendErrorCausesEarlySaveOfContext() throws Exception {
        HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository();
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, response);
        SecurityContextHolder.setContext(repo.loadContext(holder));
        SecurityContextHolder.getContext().setAuthentication(testToken);
        holder.getResponse().sendError(404);
        assertEquals(SecurityContextHolder.getContext(), request.getSession().getAttribute(SPRING_SECURITY_CONTEXT_KEY));
        assertTrue(((SaveContextOnUpdateOrErrorResponseWrapper)holder.getResponse()).isContextSaved());
        repo.saveContext(SecurityContextHolder.getContext(), holder.getRequest(), holder.getResponse());
        // Check it's still the same
        assertEquals(SecurityContextHolder.getContext(), request.getSession().getAttribute(SPRING_SECURITY_CONTEXT_KEY));
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
