package org.springframework.security.web.savedrequest;

import static org.fest.assertions.Assertions.assertThat;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.util.RequestMatcher;

/**
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class HttpSessionRequestCacheTests {

    @Test
    public void originalGetRequestDoesntMatchIncomingPost() {
        HttpSessionRequestCache cache = new HttpSessionRequestCache();

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/destination");
        MockHttpServletResponse response = new MockHttpServletResponse();
        cache.saveRequest(request, response);
        assertNotNull(request.getSession().getAttribute(HttpSessionRequestCache.SAVED_REQUEST));
        assertNotNull(cache.getRequest(request, response));

        MockHttpServletRequest newRequest = new MockHttpServletRequest("POST", "/destination");
        newRequest.setSession(request.getSession());
        assertNull(cache.getMatchingRequest(newRequest, response));

    }

    @Test
    public void requestMatcherDefinesCorrectSubsetOfCachedRequests() throws Exception {
        HttpSessionRequestCache cache = new HttpSessionRequestCache();
        cache.setRequestMatcher(new RequestMatcher() {
            public boolean matches(HttpServletRequest request) {
                return request.getMethod().equals("GET");
            }
        });

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/destination");
        MockHttpServletResponse response = new MockHttpServletResponse();
        cache.saveRequest(request, response);
        assertNull(cache.getRequest(request, response));
        assertNull(cache.getRequest(new MockHttpServletRequest(), new MockHttpServletResponse()));
        assertNull(cache.getMatchingRequest(request, response));
    }

    // SEC-2246
    @Test
    public void getRequestCustomNoClassCastException() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/destination");
        MockHttpServletResponse response = new MockHttpServletResponse();
        HttpSessionRequestCache cache = new HttpSessionRequestCache() {

            @Override
            public void saveRequest(HttpServletRequest request,
                    HttpServletResponse response) {
                request.getSession().setAttribute(SAVED_REQUEST, new CustomSavedRequest(new DefaultSavedRequest(request, new PortResolverImpl())));
            }

        };
        cache.saveRequest(request,response);

        cache.saveRequest(request, response);
        assertThat(cache.getRequest(request, response)).isInstanceOf(CustomSavedRequest.class);
    }

    private static final class CustomSavedRequest implements SavedRequest {
        private final SavedRequest delegate;

        private CustomSavedRequest(SavedRequest delegate) {
            this.delegate = delegate;
        }

        public String getRedirectUrl() {
            return delegate.getRedirectUrl();
        }

        public List<Cookie> getCookies() {
            return delegate.getCookies();
        }

        public String getMethod() {
            return delegate.getMethod();
        }

        public List<String> getHeaderValues(String name) {
            return delegate.getHeaderValues(name);
        }

        public Collection<String> getHeaderNames() {
            return delegate.getHeaderNames();
        }

        public List<Locale> getLocales() {
            return delegate.getLocales();
        }

        public String[] getParameterValues(String name) {
            return delegate.getParameterValues(name);
        }

        public Map<String, String[]> getParameterMap() {
            return delegate.getParameterMap();
        }

        private static final long serialVersionUID = 2426831999233621470L;
    }
}
