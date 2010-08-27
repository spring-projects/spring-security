package org.springframework.security.config.http

import org.springframework.beans.factory.parsing.BeanDefinitionParsingException
import org.springframework.security.config.BeanIds
import org.springframework.security.web.FilterChainProxy

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
        Map filterChains = fcp.getFilterChainMap();

        then:
        filterChains.size() == 2
        (filterChains.keySet() as List)[0].pattern == '/stateless/**'
    }

    def duplicatePatternsAreRejected () {
        when: "Two <http> elements are used"
        xml.http(pattern: '/stateless/**', 'create-session': 'stateless') {
            'http-basic'()
        }
        xml.http(pattern: '/stateless/**') {
            'form-login'()
        }
        createAppContext()
        then:
        thrown(BeanDefinitionParsingException)
    }
}
