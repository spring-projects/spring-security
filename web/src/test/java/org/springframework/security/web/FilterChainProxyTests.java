package org.springframework.security.web;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import org.junit.Before;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.firewall.FirewalledRequest;
import org.springframework.security.web.util.RequestMatcher;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.util.*;

/**
 * @author Luke Taylor
 */
@SuppressWarnings({"unchecked"})
public class FilterChainProxyTests {
    private FilterChainProxy fcp;
    private RequestMatcher matcher;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private FilterChain chain;
    private Filter filter;

    @Before
    public void setup() throws Exception {
        fcp = new FilterChainProxy();
        fcp.setFilterChainValidator(mock(FilterChainProxy.FilterChainValidator.class));
        matcher = mock(RequestMatcher.class);
        filter = mock(Filter.class);
        doAnswer(new Answer() {
                    public Object answer(InvocationOnMock inv) throws Throwable {
                        Object[] args = inv.getArguments();
                        FilterChain fc = (FilterChain) args[2];
                        HttpServletRequestWrapper extraWrapper =
                                new HttpServletRequestWrapper((HttpServletRequest) args[0]);
                        fc.doFilter(extraWrapper, (HttpServletResponse) args[1]);
                        return null;
                    }
                }).when(filter).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class), any(FilterChain.class));
        LinkedHashMap map = new LinkedHashMap();
        map.put(matcher, Arrays.asList(filter));
        fcp.setFilterChainMap(map);
        request = new MockHttpServletRequest();
        request.setServletPath("/path");
        response = new MockHttpServletResponse();
        chain = mock(FilterChain.class);
    }

    @Test
    public void toStringCallSucceeds() throws Exception {
        fcp.afterPropertiesSet();
        fcp.toString();
    }

    @Test
    public void securityFilterChainIsNotInvokedIfMatchFails() throws Exception {
        when(matcher.matches(any(HttpServletRequest.class))).thenReturn(false);
        fcp.doFilter(request, response, chain);
        assertEquals(1, fcp.getFilterChainMap().size());
        assertSame(filter, fcp.getFilterChainMap().get(matcher).get(0));

        verifyZeroInteractions(filter);
        // The actual filter chain should be invoked though
        verify(chain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
    }

    @Test
    public void originalChainIsInvokedAfterSecurityChainIfMatchSucceeds() throws Exception {
        when(matcher.matches(any(HttpServletRequest.class))).thenReturn(true);
        fcp.doFilter(request, response, chain);

        verify(filter).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class), any(FilterChain.class));
        verify(chain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
    }

    @Test
    public void originalFilterChainIsInvokedIfMatchingSecurityChainIsEmpty() throws Exception {
        LinkedHashMap map = new LinkedHashMap();
        map.put(matcher, Collections.emptyList());
        fcp.setFilterChainMap(map);

        when(matcher.matches(any(HttpServletRequest.class))).thenReturn(true);
        fcp.doFilter(request, response, chain);

        verify(chain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
    }

    @Test
    public void requestIsWrappedForMatchingAndFilteringWhenMatchIsFound() throws Exception {
        when(matcher.matches(any(HttpServletRequest.class))).thenReturn(true);
        fcp.doFilter(request, response, chain);
        verify(matcher).matches(any(FirewalledRequest.class));
        verify(filter).doFilter(any(FirewalledRequest.class), any(HttpServletResponse.class), any(FilterChain.class));
        verify(chain).doFilter(any(FirewalledRequest.class), any(HttpServletResponse.class));
    }

    @Test
    public void requestIsWrappedForMatchingAndFilteringWhenMatchIsNotFound() throws Exception {
        when(matcher.matches(any(HttpServletRequest.class))).thenReturn(false);
        fcp.doFilter(request, response, chain);
        verify(matcher).matches(any(FirewalledRequest.class));
        verifyZeroInteractions(filter);
        verify(chain).doFilter(any(FirewalledRequest.class), any(HttpServletResponse.class));
    }

}
