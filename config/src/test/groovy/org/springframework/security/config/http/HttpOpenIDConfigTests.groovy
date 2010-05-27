package org.springframework.security.config.http

import javax.servlet.http.HttpServletRequest
import org.springframework.beans.factory.parsing.BeanDefinitionParsingException
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.config.BeanIds
import org.springframework.security.openid.OpenIDAuthenticationFilter
import org.springframework.security.openid.OpenIDAuthenticationToken
import org.springframework.security.openid.OpenIDConsumer
import org.springframework.security.openid.OpenIDConsumerException
import org.springframework.security.web.FilterChainProxy
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter

/**
 *
 * @author Luke Taylor
 */
class OpenIDConfigTests extends AbstractHttpConfigTests {

    def openIDAndFormLoginWorkTogether() {
        xml.http() {
            'openid-login'()
            'form-login'()
        }
        createAppContext()

        def etf = getFilter(ExceptionTranslationFilter)
        def ap = etf.getAuthenticationEntryPoint();

        expect:
        ap.loginFormUrl == "/spring_security_login"
        // Default login filter should be present since we haven't specified any login URLs
        getFilter(DefaultLoginPageGeneratingFilter) != null
    }

    def formLoginEntryPointTakesPrecedenceIfLoginUrlIsSet() {
        xml.http() {
            'openid-login'()
            'form-login'('login-page': '/form-page')
        }
        createAppContext()

        expect:
        getFilter(ExceptionTranslationFilter).authenticationEntryPoint.loginFormUrl == '/form-page'
    }

    def openIDEntryPointTakesPrecedenceIfLoginUrlIsSet() {
        xml.http() {
            'openid-login'('login-page': '/openid-page')
            'form-login'()
        }
        createAppContext()

        expect:
        getFilter(ExceptionTranslationFilter).authenticationEntryPoint.loginFormUrl == '/openid-page'
    }

    def multipleLoginPagesCausesError() {
        when:
        xml.http() {
            'openid-login'('login-page': '/openid-page')
            'form-login'('login-page': '/form-page')
        }
        createAppContext()
        then:
        thrown(BeanDefinitionParsingException)
    }

    def openIDAndRememberMeWorkTogether() {
        xml.http() {
            interceptUrl('/**', 'ROLE_NOBODY')
            'openid-login'()
            'remember-me'()
        }
        createAppContext()

        // Default login filter should be present since we haven't specified any login URLs
        def loginFilter = getFilter(DefaultLoginPageGeneratingFilter)
        def openIDFilter = getFilter(OpenIDAuthenticationFilter)
        openIDFilter.setConsumer(new OpenIDConsumer() {
            public String beginConsumption(HttpServletRequest req, String claimedIdentity, String returnToUrl, String realm)
                    throws OpenIDConsumerException {
                return "http://testopenid.com?openid.return_to=" + returnToUrl;
            }

            public OpenIDAuthenticationToken endConsumption(HttpServletRequest req) throws OpenIDConsumerException {
                throw new UnsupportedOperationException();
            }
        })
        Set<String> returnToUrlParameters = new HashSet<String>()
        returnToUrlParameters.add(AbstractRememberMeServices.DEFAULT_PARAMETER)
        openIDFilter.setReturnToUrlParameters(returnToUrlParameters)
        assert loginFilter.openIDrememberMeParameter != null

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        when: "Initial request is made"
        FilterChainProxy fcp = appContext.getBean(BeanIds.FILTER_CHAIN_PROXY)
        request.setServletPath("/something.html")
        fcp.doFilter(request, response, new MockFilterChain())
        then: "Redirected to login"
        response.getRedirectedUrl().endsWith("/spring_security_login")
        when: "Login page is requested"
        request.setServletPath("/spring_security_login")
        request.setRequestURI("/spring_security_login")
        response = new MockHttpServletResponse()
        fcp.doFilter(request, response, new MockFilterChain())
        then: "Remember-me choice is added to page"
        response.getContentAsString().contains(AbstractRememberMeServices.DEFAULT_PARAMETER)
        when: "Login is submitted with remember-me selected"
        request.setRequestURI("/j_spring_openid_security_check")
        request.setParameter(OpenIDAuthenticationFilter.DEFAULT_CLAIMED_IDENTITY_FIELD, "http://hey.openid.com/")
        request.setParameter(AbstractRememberMeServices.DEFAULT_PARAMETER, "on")
        response = new MockHttpServletResponse();
        fcp.doFilter(request, response, new MockFilterChain());
        String expectedReturnTo = request.getRequestURL().append("?")
                                        .append(AbstractRememberMeServices.DEFAULT_PARAMETER)
                                        .append("=").append("on").toString();
        then: "return_to URL contains remember-me choice"
        response.getRedirectedUrl() == "http://testopenid.com?openid.return_to=" + expectedReturnTo
    }

    def openIDWithAttributeExchangeConfigurationIsParsedCorrectly() {
        xml.http() {
            'openid-login'() {
                'attribute-exchange'() {
                    'openid-attribute'(name: 'nickname', type: 'http://schema.openid.net/namePerson/friendly')
                    'openid-attribute'(name: 'email', type: 'http://schema.openid.net/contact/email', required: 'true',
                            'count': '2')
                }
            }
        }
        createAppContext()

        List attributes = getFilter(OpenIDAuthenticationFilter).consumer.attributesToFetchFactory.createAttributeList('http://someid')

        expect:
        attributes.size() == 2
        attributes[0].name == 'nickname'
        attributes[0].type == 'http://schema.openid.net/namePerson/friendly'
        attributes[0].required == false
        attributes[1].required == true
        attributes[1].getCount() == 2
    }
}
