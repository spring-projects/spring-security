package org.springframework.security.config.http

import org.springframework.security.util.FieldUtils
import org.springframework.security.web.authentication.logout.LogoutFilter

/**
 *
 * @author Rob Winch
 */
class LogoutConfigTests extends AbstractHttpConfigTests {

    def 'SEC-2455: logout@logout-url'() {
        when:
            httpAutoConfig {
                'logout'('logout-url':'/logout')
            }
            createAppContext()

            def lf = getFilter(LogoutFilter);

        then:
            lf.filterProcessesUrl == null // SEC-2455 setFilterProcessesUrl was not invoked
            FieldUtils.getFieldValue(lf,'logoutRequestMatcher.filterProcessesUrl') == '/logout'
    }
}