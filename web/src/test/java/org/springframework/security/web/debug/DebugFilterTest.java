package org.springframework.security.web.debug;

import static org.fest.assertions.Assertions.assertThat;
import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Collections;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareOnlyThisForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.internal.WhiteboxImpl;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.FilterChainProxy;

/**
 *
 * @author Rob Winch
 *
 */
@RunWith(PowerMockRunner.class)
@PrepareOnlyThisForTest(Logger.class)
public class DebugFilterTest {
    @Captor
    private ArgumentCaptor<HttpServletRequest> requestCaptor;
    @Captor
    private ArgumentCaptor<String> logCaptor;

    @Mock
    private HttpServletRequest request;
    @Mock
    private HttpServletResponse response;
    @Mock
    private FilterChain filterChain;
    @Mock
    private FilterChainProxy fcp;
    @Mock
    private Logger logger;

    private String requestAttr;

    private DebugFilter filter;

    @Before
    public void setUp() {
        when(request.getHeaderNames()).thenReturn(Collections.enumeration(Collections.<String>emptyList()));
        when(request.getServletPath()).thenReturn("/login");
        filter = new DebugFilter(fcp);
        WhiteboxImpl.setInternalState(filter, Logger.class, logger);
        requestAttr = WhiteboxImpl.getInternalState(filter, "ALREADY_FILTERED_ATTR_NAME", filter.getClass());
    }

    @Test
    public void doFilterProcessesRequests() throws Exception {
        filter.doFilter(request, response, filterChain);

        verify(logger).info(anyString());
        verify(request).setAttribute(requestAttr, Boolean.TRUE);
        verify(fcp).doFilter(requestCaptor.capture(), eq(response), eq(filterChain));
        assertEquals(DebugRequestWrapper.class,requestCaptor.getValue().getClass());
        verify(request).removeAttribute(requestAttr);
    }

    // SEC-1901
    @Test
    public void doFilterProcessesForwardedRequests() throws Exception {
        when(request.getAttribute(requestAttr)).thenReturn(Boolean.TRUE);
        HttpServletRequest request = new DebugRequestWrapper(this.request);

        filter.doFilter(request, response, filterChain);

        verify(logger).info(anyString());
        verify(fcp).doFilter(request, response, filterChain);
        verify(this.request,never()).removeAttribute(requestAttr);
    }

    @Test
    public void doFilterDoesNotWrapWithDebugRequestWrapperAgain() throws Exception {
        when(request.getAttribute(requestAttr)).thenReturn(Boolean.TRUE);
        HttpServletRequest fireWalledRequest = new HttpServletRequestWrapper(new DebugRequestWrapper(this.request));

        filter.doFilter(fireWalledRequest, response, filterChain);

        verify(fcp).doFilter(fireWalledRequest, response, filterChain);
    }

    @Test
    public void doFilterLogsProperly() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("GET");
        request.setServletPath("/path");
        request.setPathInfo("/");
        request.addHeader("A", "A Value");
        request.addHeader("A", "Another Value");
        request.addHeader("B", "B Value");

        filter.doFilter(request, response, filterChain);

        verify(logger).info(logCaptor.capture());

        assertThat(logCaptor.getValue()).isEqualTo("Request received for GET '/path/':\n" +
                "\n" +
                request + "\n" +
                "\n" +
                "servletPath:/path\n" +
                "pathInfo:/\n" +
                "headers: \n" +
                "A: A Value, Another Value\n" +
                "B: B Value\n" +
                "\n" +
                "\n" +
                "Security filter chain: no match");
    }
}