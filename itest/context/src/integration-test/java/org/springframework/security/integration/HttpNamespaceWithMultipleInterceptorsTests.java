package org.springframework.security.integration;

import static org.junit.Assert.*;

import javax.servlet.http.HttpSession;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@ContextConfiguration(locations={"/http-extra-fsi-app-context.xml"})
@RunWith(SpringJUnit4ClassRunner.class)
public class HttpNamespaceWithMultipleInterceptorsTests {

    @Autowired
    private FilterChainProxy fcp;

    @Test
    public void requestThatIsMatchedByDefaultInterceptorIsAllowed() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/somefile.html");
        request.setSession(createAuthenticatedSession("ROLE_0", "ROLE_1", "ROLE_2"));
        MockHttpServletResponse response = new MockHttpServletResponse();
        fcp.doFilter(request, response, new MockFilterChain());
        assertEquals(200, response.getStatus());
    }

    @Test
    public void securedUrlAccessIsRejectedWithoutRequiredRole() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/secure/somefile.html");
        request.setSession(createAuthenticatedSession("ROLE_0"));
        MockHttpServletResponse response = new MockHttpServletResponse();
        fcp.doFilter(request, response, new MockFilterChain());
        assertEquals(403, response.getStatus());
    }

    public HttpSession createAuthenticatedSession(String... roles) {
        MockHttpSession session = new MockHttpSession();
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("bob", "bobspassword", roles));
        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, SecurityContextHolder.getContext());
        SecurityContextHolder.clearContext();
        return session;
    }


}
