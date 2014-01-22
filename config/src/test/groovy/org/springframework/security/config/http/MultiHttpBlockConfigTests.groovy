package org.springframework.security.config.http

import static org.mockito.Mockito.*

import org.powermock.api.mockito.internal.verification.VerifyNoMoreInteractions;
import org.springframework.beans.factory.parsing.BeanDefinitionParsingException
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.BeanIds
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.FilterChainProxy
import org.junit.Assert
import org.springframework.beans.factory.BeanCreationException
import org.springframework.security.web.SecurityFilterChain

/**
 * Tests scenarios with multiple &lt;http&gt; elements.
 *
 * @author Luke Taylor
 */
class MultiHttpBlockConfigTests extends AbstractHttpConfigTests {

    def multipleHttpElementsAreSupported () {
        when: "Two <http> elements are used"
        xml.http(pattern: '/stateless/**', 'create-session': 'stateless') {
            'http-basic'()
        }
        xml.http(pattern: '/stateful/**') {
            'form-login'()
        }
        createAppContext()
        FilterChainProxy fcp = appContext.getBean(BeanIds.FILTER_CHAIN_PROXY)
        def filterChains = fcp.getFilterChains();

        then:
        filterChains.size() == 2
        filterChains[0].requestMatcher.pattern == '/stateless/**'
    }

    def duplicateHttpElementsAreRejected () {
        when: "Two <http> elements are used"
        xml.http('create-session': 'stateless') {
            'http-basic'()
        }
        xml.http() {
            'form-login'()
        }
        createAppContext()
        then:
        BeanCreationException e = thrown()
        e.cause instanceof IllegalArgumentException
    }

    def duplicatePatternsAreRejected () {
        when: "Two <http> elements with the same pattern are used"
        xml.http(pattern: '/stateless/**', 'create-session': 'stateless') {
            'http-basic'()
        }
        xml.http(pattern: '/stateless/**') {
            'form-login'()
        }
        createAppContext()
        then:
        BeanCreationException e = thrown()
        e.cause instanceof IllegalArgumentException
    }


    def 'SEC-1937: http@authentication-manager-ref and multi authentication-mananager'() {
        setup:
            xml.http('authentication-manager-ref' : 'authManager', 'pattern' : '/first/**') {
                'form-login'('login-processing-url': '/first/login')
            }
            xml.http('authentication-manager-ref' : 'authManager2') {
                'form-login'()
            }
            mockBean(UserDetailsService,'uds')
            mockBean(UserDetailsService,'uds2')
            createAppContext("""
<authentication-manager id="authManager">
    <authentication-provider user-service-ref="uds" />
</authentication-manager>
<authentication-manager id="authManager2">
    <authentication-provider user-service-ref="uds2" />
</authentication-manager>
""")
            UserDetailsService uds = appContext.getBean('uds')
            UserDetailsService uds2 = appContext.getBean('uds2')
        when:
            MockHttpServletRequest request = new MockHttpServletRequest()
            MockHttpServletResponse response = new MockHttpServletResponse()
            MockFilterChain chain = new MockFilterChain()
            request.servletPath = "/first/login"
            request.requestURI = "/first/login"
            request.method = 'POST'
            springSecurityFilterChain.doFilter(request,response,chain)
        then:
            verify(uds).loadUserByUsername(anyString()) || true
            verifyZeroInteractions(uds2) || true
        when:
            MockHttpServletRequest request2 = new MockHttpServletRequest()
            MockHttpServletResponse response2 = new MockHttpServletResponse()
            MockFilterChain chain2 = new MockFilterChain()
            request2.servletPath = "/j_spring_security_check"
            request2.requestURI = "/j_spring_security_check"
            request2.method = 'POST'
            springSecurityFilterChain.doFilter(request2,response2,chain2)
        then:
            verify(uds2).loadUserByUsername(anyString()) || true
            verifyNoMoreInteractions(uds) || true
    }

    def multipleAuthenticationManagersWorks () {
        xml.http(name: 'basic', pattern: '/basic/**', ) {
            'http-basic'()
        }
        xml.http(pattern: '/form/**') {
            'form-login'()
        }
        createAppContext()
        FilterChainProxy fcp = appContext.getBean(BeanIds.FILTER_CHAIN_PROXY)
        SecurityFilterChain basicChain = fcp.filterChains[0];

        expect:
        Assert.assertSame (basicChain, appContext.getBean('basic'))
    }
}
