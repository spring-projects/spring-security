package org.springframework.security.util;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.*;

import org.junit.Before;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.firewall.FirewalledRequest;
import org.springframework.security.firewall.HttpFirewall;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.*;

/**
 * @author Luke Taylor
 * @author Rob Winch
 */
@SuppressWarnings({"unchecked"})
public class FilterChainProxyTests {
    private FilterChainProxy fcp;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private FilterChain chain;
    private Filter filter;

    @Before
    public void setup() throws Exception {
        fcp = new FilterChainProxy();
        filter = mock(Filter.class);
        doAnswer(new Answer() {
                    public Object answer(InvocationOnMock inv) throws Throwable {
                        Object[] args = inv.getArguments();
                        FilterChain fc = (FilterChain) args[2];
                        fc.doFilter((HttpServletRequest) args[0], (HttpServletResponse) args[1]);
                        return null;
                    }
                }).when(filter).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class), any(FilterChain.class));
        LinkedHashMap map = new LinkedHashMap();
        map.put("/match", Arrays.asList(filter));
        fcp.setFilterChainMap(map);
        request = new MockHttpServletRequest();
        request.setServletPath("/match");
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
        request.setServletPath("/nomatch");
        fcp.doFilter(request, response, chain);
        assertEquals(1, fcp.getFilterChainMap().size());

        verifyZeroInteractions(filter);
        // The actual filter chain should be invoked though
        verify(chain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
    }

    @Test
    public void originalChainIsInvokedAfterSecurityChainIfMatchSucceeds() throws Exception {
        fcp.doFilter(request, response, chain);

        verify(filter).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class), any(FilterChain.class));
        verify(chain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
    }

    @Test
    public void originalFilterChainIsInvokedIfMatchingSecurityChainIsEmpty() throws Exception {
        LinkedHashMap map = new LinkedHashMap();
        map.put("/match", Collections.emptyList());
        fcp.setFilterChainMap(map);

        fcp.doFilter(request, response, chain);

        verify(chain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
    }

    @Test
    public void requestIsWrappedForFilteringWhenMatchIsFound() throws Exception {
        fcp.doFilter(request, response, chain);
        verify(filter).doFilter(any(FirewalledRequest.class), any(HttpServletResponse.class), any(FilterChain.class));
        verify(chain).doFilter(any(FirewalledRequest.class), any(HttpServletResponse.class));
    }

    @Test
    public void requestIsWrappedForFilteringWhenMatchIsNotFound() throws Exception {
        request.setServletPath("/nomatch");
        fcp.doFilter(request, response, chain);
        verifyZeroInteractions(filter);
        verify(chain).doFilter(any(FirewalledRequest.class), any(HttpServletResponse.class));
    }

    // SEC-1639
    @Test
    public void bothWrappersAreResetWithNestedFcps() throws Exception {
        HttpFirewall fw = mock(HttpFirewall.class);
        FilterChainProxy firstFcp = new FilterChainProxy();
        LinkedHashMap fcm = new LinkedHashMap();
        fcm.put("/match", Arrays.asList(fcp));
        firstFcp.setFilterChainMap(fcm);
        firstFcp.setFirewall(fw);
        fcp.setFirewall(fw);
        FirewalledRequest firstFwr = mock(FirewalledRequest.class, "firstFwr");
        when(firstFwr.getRequestURI()).thenReturn("/match");
        when(firstFwr.getContextPath()).thenReturn("");
        FirewalledRequest fwr = mock(FirewalledRequest.class, "fwr");
        when(fwr.getRequestURI()).thenReturn("/match");
        when(fwr.getContextPath()).thenReturn("");
        when(fw.getFirewalledResponse(any(HttpServletResponse.class))).thenReturn(response);
        when(fw.getFirewalledRequest(request)).thenReturn(firstFwr);
        when(fw.getFirewalledRequest(firstFwr)).thenReturn(fwr);
        when(fwr.getRequest()).thenReturn(firstFwr);
        when(firstFwr.getRequest()).thenReturn(request);
        firstFcp.doFilter(request, response, chain);
        verify(firstFwr).reset();
        verify(fwr).reset();
    }
}
