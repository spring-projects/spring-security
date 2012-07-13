package org.springframework.security.config.http

import org.springframework.beans.factory.BeanCreationException
import org.springframework.security.util.FieldUtils
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter

/**
 *
 * @author Luke Taylor
 */
class FormLoginConfigTests extends AbstractHttpConfigTests {

    def formLoginWithNoLoginPageAddsDefaultLoginPageFilter() {
        httpAutoConfig('ant') {
            form-login()
        }
        createAppContext()
        filtersMatchExpectedAutoConfigList();
    }

    def 'Form login alwaysUseDefaultTarget sets correct property'() {
        xml.http {
            'form-login'('default-target-url':'/default', 'always-use-default-target': 'true')
        }
        createAppContext()
        def filter = getFilter(UsernamePasswordAuthenticationFilter.class);

        expect:
        FieldUtils.getFieldValue(filter, 'successHandler.defaultTargetUrl') == '/default';
        FieldUtils.getFieldValue(filter, 'successHandler.alwaysUseDefaultTargetUrl');
    }

    def 'form-login attributes support SpEL'() {
        setup:
        def spelUrl = '#{T(org.springframework.security.config.http.WebConfigUtilsTest).URL}'
        def expectedUrl = WebConfigUtilsTest.URL
        when:
        xml.http {
            'form-login'('default-target-url': spelUrl , 'authentication-failure-url': spelUrl, 'login-page': spelUrl)
        }
        createAppContext()
        def unPwdFilter = getFilter(UsernamePasswordAuthenticationFilter)
        def exTransFilter = getFilter(ExceptionTranslationFilter)

        then:
        unPwdFilter.successHandler.defaultTargetUrl == expectedUrl
        unPwdFilter
        FieldUtils.getFieldValue(unPwdFilter, 'successHandler.defaultTargetUrl') == expectedUrl
        FieldUtils.getFieldValue(unPwdFilter, 'failureHandler.defaultFailureUrl') == expectedUrl
        FieldUtils.getFieldValue(exTransFilter, 'authenticationEntryPoint.loginFormUrl') == expectedUrl
    }

    def invalidLoginPageIsDetected() {
        when:
        xml.http {
            'form-login'('login-page': 'noLeadingSlash')
        }
        createAppContext()

        then:
        BeanCreationException e = thrown();
    }

    def invalidDefaultTargetUrlIsDetected() {
        when:
        xml.http {
            'form-login'('default-target-url': 'noLeadingSlash')
        }
        createAppContext()

        then:
        BeanCreationException e = thrown();
    }

    def customSuccessAndFailureHandlersCanBeSetThroughTheNamespace() {
        xml.http {
            'form-login'('authentication-success-handler-ref': 'sh', 'authentication-failure-handler-ref':'fh')
        }
        bean('sh', SavedRequestAwareAuthenticationSuccessHandler.class.name)
        bean('fh', SimpleUrlAuthenticationFailureHandler.class.name)
        createAppContext()

        def apf = getFilter(UsernamePasswordAuthenticationFilter.class);

        expect:
        FieldUtils.getFieldValue(apf, "successHandler") == appContext.getBean("sh");
        FieldUtils.getFieldValue(apf, "failureHandler") == appContext.getBean("fh")
    }

    def usernameAndPasswordParametersCanBeSetThroughNamespace() {
        xml.http {
            'form-login'('username-parameter': 'xname', 'password-parameter':'xpass')
        }
        createAppContext()

        def apf = getFilter(UsernamePasswordAuthenticationFilter.class);

        expect:
        apf.usernameParameter == 'xname';
        apf.passwordParameter == 'xpass'
    }
}
