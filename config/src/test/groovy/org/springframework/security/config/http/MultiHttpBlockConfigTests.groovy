package org.springframework.security.config.http

import org.springframework.beans.factory.parsing.BeanDefinitionParsingException
import org.springframework.security.config.BeanIds
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



    def namedFilterChainIsExposedAsABean () {
        xml.http(name: 'basic', pattern: '/basic/**', 'create-session': 'stateless') {
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
