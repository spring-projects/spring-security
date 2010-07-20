package org.springframework.security.config.http

import org.springframework.beans.factory.config.PropertyPlaceholderConfigurer
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.access.ConfigAttribute
import org.springframework.security.access.SecurityConfig
import org.springframework.security.util.FieldUtils
import org.springframework.security.web.PortMapperImpl
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.access.channel.ChannelProcessingFilter
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter

class PlaceHolderAndELConfigTests extends AbstractHttpConfigTests {

    def setup() {
        // Add a PropertyPlaceholderConfigurer to the context for all the tests
        xml.'b:bean'('class': PropertyPlaceholderConfigurer.class.name)
    }

    def unsecuredPatternSupportsPlaceholderForPattern() {
        System.setProperty("pattern.nofilters", "/unprotected");

        xml.http(pattern: '${pattern.nofilters}', security: 'none')
        httpAutoConfig() {
            interceptUrl('/**', 'ROLE_A')
        }
        createAppContext()

        List filters = getFilters("/unprotected");

        expect:
        filters.size() == 0
    }

    // SEC-1201
    def interceptUrlsAndFormLoginSupportPropertyPlaceholders() {
        System.setProperty("secure.Url", "/Secure");
        System.setProperty("secure.role", "ROLE_A");
        System.setProperty("login.page", "/loginPage");
        System.setProperty("default.target", "/defaultTarget");
        System.setProperty("auth.failure", "/authFailure");

        xml.http(pattern: '${login.page}', security: 'none')
        xml.http {
            interceptUrl('${secure.Url}', '${secure.role}')
            'form-login'('login-page':'${login.page}', 'default-target-url': '${default.target}',
                'authentication-failure-url':'${auth.failure}');
        }
        createAppContext();

        expect:
        propertyValuesMatchPlaceholders()
        getFilters("/loginPage").size() == 0
    }

    // SEC-1309
    def interceptUrlsAndFormLoginSupportEL() {
        System.setProperty("secure.url", "/Secure");
        System.setProperty("secure.role", "ROLE_A");
        System.setProperty("login.page", "/loginPage");
        System.setProperty("default.target", "/defaultTarget");
        System.setProperty("auth.failure", "/authFailure");

        xml.http {
            interceptUrl("#{systemProperties['secure.url']}", "#{systemProperties['secure.role']}")
            'form-login'('login-page':"#{systemProperties['login.page']}", 'default-target-url': "#{systemProperties['default.target']}",
                'authentication-failure-url':"#{systemProperties['auth.failure']}");
        }
        createAppContext()

        expect:
        propertyValuesMatchPlaceholders()
    }

    private void propertyValuesMatchPlaceholders() {
        // Check the security attribute
        def fis = getFilter(FilterSecurityInterceptor);
        def fids = fis.getSecurityMetadataSource();
        Collection attrs = fids.getAttributes(createFilterinvocation("/secure", null));
        assert attrs.size() == 1
        assert attrs.contains(new SecurityConfig("ROLE_A"))

        // Check the form login properties are set
        def apf = getFilter(UsernamePasswordAuthenticationFilter)
        assert FieldUtils.getFieldValue(apf, "successHandler.defaultTargetUrl") == '/defaultTarget'
        assert "/authFailure" == FieldUtils.getFieldValue(apf, "failureHandler.defaultFailureUrl")

        def etf = getFilter(ExceptionTranslationFilter)
        assert "/loginPage"== etf.authenticationEntryPoint.loginFormUrl
    }

    def portMappingsWorkWithPlaceholdersAndEL() {
        System.setProperty("http", "9080");
        System.setProperty("https", "9443");

        httpAutoConfig {
            'port-mappings'() {
                'port-mapping'(http: '#{systemProperties.http}', https: '${https}')
            }
        }
        createAppContext();

        def pm = (appContext.getBeansOfType(PortMapperImpl).values() as List)[0];

        expect:
        pm.getTranslatedPortMappings().size() == 1
        pm.lookupHttpPort(9443) == 9080
        pm.lookupHttpsPort(9080) == 9443
    }

    def requiresChannelSupportsPlaceholder() {
        System.setProperty("secure.url", "/secure");
        System.setProperty("required.channel", "https");

        httpAutoConfig {
            'intercept-url'(pattern: '${secure.url}', 'requires-channel': '${required.channel}')
        }
        createAppContext();
        List filters = getFilters("/secure");

        expect:
        filters.size() == AUTO_CONFIG_FILTERS + 1
        filters[0] instanceof ChannelProcessingFilter
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/secure");
        MockHttpServletResponse response = new MockHttpServletResponse();
        filters[0].doFilter(request, response, new MockFilterChain());
        response.getRedirectedUrl().startsWith("https")
    }

    def accessDeniedPageWorksWithPlaceholders() {
        System.setProperty("accessDenied", "/go-away");
        xml.http('auto-config': 'true', 'access-denied-page': '${accessDenied}')
        createAppContext();

        expect:
        FieldUtils.getFieldValue(getFilter(ExceptionTranslationFilter.class), "accessDeniedHandler.errorPage") == '/go-away'
    }

    def accessDeniedHandlerPageWorksWithEL() {
        httpAutoConfig {
            'access-denied-handler'('error-page': "#{'/go' + '-away'}")
        }
        createAppContext()

        expect:
        getFilter(ExceptionTranslationFilter).accessDeniedHandler.errorPage == '/go-away'
    }

}
