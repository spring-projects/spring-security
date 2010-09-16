package org.springframework.security.config.http

import org.springframework.beans.factory.BeanCreationException
import org.springframework.beans.factory.parsing.BeanDefinitionParsingException
import org.springframework.security.web.access.AccessDeniedHandlerImpl
import org.springframework.security.web.access.ExceptionTranslationFilter

/**
 *
 * @author Luke Taylor
 */
class AccessDeniedConfigTests extends AbstractHttpConfigTests {
    private static final String ACCESS_DENIED_PAGE = 'access-denied-page';

    def accessDeniedPageAttributeIsSupported() {
        httpAccessDeniedPage ('/accessDenied') { }
        createAppContext();

        expect:
        getFilter(ExceptionTranslationFilter.class).accessDeniedHandler.errorPage == '/accessDenied'

    }

    def invalidAccessDeniedUrlIsDetected() {
        when:
        httpAccessDeniedPage ('noLeadingSlash') { }
        createAppContext();
        then:
        thrown(BeanCreationException)
    }

    def accessDeniedHandlerIsSetCorectly() {
        httpAutoConfig() {
            'access-denied-handler'(ref: 'adh')
        }
        bean('adh', AccessDeniedHandlerImpl)
        createAppContext();

        def filter = getFilter(ExceptionTranslationFilter.class);
        def adh = appContext.getBean("adh");

        expect:
        filter.accessDeniedHandler == adh
    }

    def void accessDeniedPageAndAccessDeniedHandlerAreMutuallyExclusive() {
        when:
        httpAccessDeniedPage ('/accessDenied') {
            'access-denied-handler'('error-page': '/go-away')
        }
        createAppContext();
        then:
        thrown(BeanDefinitionParsingException)
    }

    def void accessDeniedHandlerPageAndRefAreMutuallyExclusive() {
        when:
        httpAutoConfig {
            'access-denied-handler'('error-page': '/go-away', ref: 'adh')
        }
        createAppContext();
        bean('adh', AccessDeniedHandlerImpl)
        then:
        thrown(BeanDefinitionParsingException)
    }

    def httpAccessDeniedPage(String page, Closure c) {
        xml.http(['auto-config': 'true', 'access-denied-page': page], c)
    }
}
