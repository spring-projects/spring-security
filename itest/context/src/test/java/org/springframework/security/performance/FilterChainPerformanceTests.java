package org.springframework.security.performance;

import java.util.Arrays;
import java.util.List;

import javax.servlet.http.HttpSession;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.GrantedAuthorityImpl;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.util.StopWatch;

/**
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.0
 */
@ContextConfiguration(locations={"/filter-chain-performance-app-context.xml"})
@RunWith(SpringJUnit4ClassRunner.class)
public class FilterChainPerformanceTests {
    private static final int N_INVOCATIONS = 1000;
    private static final int N_AUTHORITIES = 200;
    private static StopWatch sw = new StopWatch("Filter Chain Performance Tests");

    private final UsernamePasswordAuthenticationToken user = new UsernamePasswordAuthenticationToken("bob", "bobspassword", createRoles(N_AUTHORITIES));
    private HttpSession session;

    @Autowired
    @Qualifier("fcpMinimalStack")
    private FilterChainProxy minimalStack;

    @Autowired
    @Qualifier("fcpFullStack")
    private FilterChainProxy fullStack;

    @Before
    public void createAuthenticatedSession() {
        session = new MockHttpSession();
        SecurityContextHolder.getContext().setAuthentication(user);
        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, SecurityContextHolder.getContext());
        SecurityContextHolder.clearContext();
    }

    @After
    public void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @AfterClass
    public static void dumpStopWatch() {
        System.out.println(sw.prettyPrint());
    }

    private MockHttpServletRequest createRequest(String url) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSession(session);
        request.setServletPath(url);
        request.setMethod("GET");
        return request;
    }

    private void runWithStack(FilterChainProxy stack) throws Exception {
        for(int i = 0; i < N_INVOCATIONS; i++) {
            MockHttpServletRequest request = createRequest("/somefile.html");
            stack.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
            session = request.getSession();
        }
    }

    @Test
    public void minimalStackInvocation() throws Exception {
        sw.start("Run with Minimal Filter Stack");
        runWithStack(minimalStack);
        sw.stop();
    }

    @Test
    public void fullStackInvocation() throws Exception {
        sw.start("Run with Full Filter Stack");
        runWithStack(fullStack);
        sw.stop();
    }

    /**
     * Creates data from 1 to N_AUTHORITIES in steps of 10, performing N_INVOCATIONS for each
     */
    @Test
    public void provideDataOnScalingWithNumberOfAuthoritiesUserHas() throws Exception {
        StopWatch sw = new StopWatch("Scaling with nAuthorities");
        for (int user=0; user < N_AUTHORITIES/10; user ++) {
            int nAuthorities = user == 0 ? 1 : user*10;
            SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("bob", "bobspassword", createRoles(nAuthorities)));
            session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, SecurityContextHolder.getContext());
            SecurityContextHolder.clearContext();
            sw.start(Integer.toString(nAuthorities) + " authorities");
            runWithStack(minimalStack);
            System.out.println(sw.shortSummary());
            sw.stop();
        }
        System.out.println(sw.prettyPrint());
    }

    private List<GrantedAuthority> createRoles(int howMany) {
     // This is always the worst case scenario - the required role is ROLE_1, but they are created in reverse order
        GrantedAuthority[] roles = new GrantedAuthority[howMany];

        for (int i = howMany - 1; i >=0 ; i--) {
            roles[i] = new GrantedAuthorityImpl("ROLE_" + i);
        }

        return Arrays.asList(roles);
    }
}
