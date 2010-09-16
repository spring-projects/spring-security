package org.springframework.security.config.http

import javax.servlet.Filter
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.config.AbstractXmlConfigTests
import org.springframework.security.config.BeanIds
import org.springframework.security.web.FilterInvocation

abstract class AbstractHttpConfigTests extends AbstractXmlConfigTests {
    final int AUTO_CONFIG_FILTERS = 11;

    def httpAutoConfig(Closure c) {
        xml.http('auto-config': 'true', c)
    }

    def httpAutoConfig(String matcher, Closure c) {
        xml.http(['auto-config': 'true', 'request-matcher': matcher], c)
    }

    def interceptUrl(String path, String authz) {
        xml.'intercept-url'(pattern: path, access: authz)
    }

    def interceptUrl(String path, String httpMethod, String authz) {
        xml.'intercept-url'(pattern: path, method: httpMethod, access: authz)
    }

    Filter getFilter(Class type) {
        List filters = getFilters("/any");

        for (f in filters) {
            if (f.class.isAssignableFrom(type)) {
                return f;
            }
        }

        return null;
    }

    List getFilters(String url) {
        def fcp = appContext.getBean(BeanIds.FILTER_CHAIN_PROXY);
        return fcp.getFilters(url)
    }

    FilterInvocation createFilterinvocation(String path, String method) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod(method);
        request.setRequestURI(null);
        request.setServletPath(path);

        return new FilterInvocation(request, new MockHttpServletResponse(), new MockFilterChain());
    }
}
