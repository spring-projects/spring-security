/*
 * Copyright 2002-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.config.http

import org.springframework.beans.factory.BeanCreationException
import org.springframework.beans.factory.parsing.BeanDefinitionParsingException
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.web.FilterChainProxy
import org.springframework.security.web.header.HeaderWriterFilter
import org.springframework.security.web.header.writers.StaticHeadersWriter
import org.springframework.security.web.util.AnyRequestMatcher

/**
 *
 * @author Rob Winch
 */
class HttpHeadersConfigTests extends AbstractHttpConfigTests {

    def 'no http headers filter'() {
        httpAutoConfig {
        }
        createAppContext()

        def hf = getFilter(HeaderWriterFilter)

        expect:
        !hf
    }

    def 'http headers with empty headers'() {
        setup:
            httpAutoConfig {
                'headers'()
            }
            createAppContext()
        when:
            def hf = getFilter(HeaderWriterFilter)
            MockHttpServletResponse response = new MockHttpServletResponse()
            hf.doFilter(new MockHttpServletRequest(secure:true), response, new MockFilterChain())
        then:
            assertHeaders(response, ['X-Content-Type-Options':'nosniff',
                                     'X-Frame-Options':'DENY',
                                     'Strict-Transport-Security': 'max-age=31536000 ; includeSubDomains',
                                     'Cache-Control': 'no-cache,no-store,max-age=0,must-revalidate',
                                     'Pragma':'no-cache',
                                     'X-XSS-Protection' : '1; mode=block'])
    }

    def 'http headers content-type-options'() {
        httpAutoConfig {
            'headers'() {
                'content-type-options'()
            }
        }
        createAppContext()

        def hf = getFilter(HeaderWriterFilter)
        MockHttpServletResponse response = new MockHttpServletResponse()
        hf.doFilter(new MockHttpServletRequest(), response, new MockFilterChain())

        expect:
        assertHeaders(response, ['X-Content-Type-Options':'nosniff'])
    }

    def 'http headers frame-options defaults to DENY'() {
        httpAutoConfig {
            'headers'() {
                'frame-options'()
            }
        }
        createAppContext()

        def hf = getFilter(HeaderWriterFilter)
        MockHttpServletResponse response = new MockHttpServletResponse()
        hf.doFilter(new MockHttpServletRequest(), response, new MockFilterChain())

        expect:
        assertHeaders(response, ['X-Frame-Options':'DENY'])
    }

    def 'http headers frame-options DENY'() {
        httpAutoConfig {
            'headers'() {
                'frame-options'(policy : 'DENY')
            }
        }
        createAppContext()

        def hf = getFilter(HeaderWriterFilter)
        MockHttpServletResponse response = new MockHttpServletResponse()
        hf.doFilter(new MockHttpServletRequest(), response, new MockFilterChain())

        expect:
        assertHeaders(response, ['X-Frame-Options':'DENY'])
    }

    def 'http headers frame-options SAMEORIGIN'() {
        httpAutoConfig {
            'headers'() {
                'frame-options'(policy : 'SAMEORIGIN')
            }
        }
        createAppContext()

        def hf = getFilter(HeaderWriterFilter)
        MockHttpServletResponse response = new MockHttpServletResponse()
        hf.doFilter(new MockHttpServletRequest(), response, new MockFilterChain())

        expect:
        assertHeaders(response, ['X-Frame-Options':'SAMEORIGIN'])
    }

    def 'http headers frame-options ALLOW-FROM no origin reports error'() {
        when:
        httpAutoConfig {
            'headers'() {
                'frame-options'(policy : 'ALLOW-FROM', strategy : 'static')
            }
        }
        createAppContext()

        def hf = getFilter(HeaderWriterFilter)

        then:
        BeanDefinitionParsingException e = thrown()
        e.message.contains "Strategy requires a 'value' to be set." // FIME better error message?
    }

    def 'http headers frame-options ALLOW-FROM spaces only origin reports error'() {
        when:
        httpAutoConfig {
            'headers'() {
                'frame-options'(policy : 'ALLOW-FROM', strategy: 'static', value : ' ')
            }
        }
        createAppContext()

        def hf = getFilter(HeaderWriterFilter)

        then:
        BeanDefinitionParsingException e = thrown()
        e.message.contains "Strategy requires a 'value' to be set." // FIME better error message?
    }

    def 'http headers frame-options ALLOW-FROM'() {
        when:
        httpAutoConfig {
            'headers'() {
                'frame-options'(policy : 'ALLOW-FROM', strategy: 'static', value : 'https://example.com')
            }
        }
        createAppContext()

        def hf = getFilter(HeaderWriterFilter)
        MockHttpServletResponse response = new MockHttpServletResponse()
        hf.doFilter(new MockHttpServletRequest(), response, new MockFilterChain())

        then:
        assertHeaders(response, ['X-Frame-Options':'ALLOW-FROM https://example.com'])
    }

    def 'http headers header a=b'() {
        when:
        httpAutoConfig {
            'headers'() {
                'header'(name : 'a', value: 'b')
            }
        }
        createAppContext()

        def hf = getFilter(HeaderWriterFilter)
        MockHttpServletResponse response = new MockHttpServletResponse()
        hf.doFilter(new MockHttpServletRequest(), response, new MockFilterChain())

        then:
        assertHeaders(response, ['a':'b'])
    }

    def 'http headers header a=b and c=d'() {
        when:
        httpAutoConfig {
            'headers'() {
                'header'(name : 'a', value: 'b')
                'header'(name : 'c', value: 'd')
            }
        }
        createAppContext()

        def hf = getFilter(HeaderWriterFilter)
        MockHttpServletResponse response = new MockHttpServletResponse()
        hf.doFilter(new MockHttpServletRequest(), response, new MockFilterChain())

        then:
        assertHeaders(response , ['a':'b', 'c':'d'])
    }

    def 'http headers with ref'() {
        setup:
            httpAutoConfig {
                'headers'() {
                    'header'(ref:'headerWriter')
                }
            }
            xml.'b:bean'(id: 'headerWriter', 'class': StaticHeadersWriter.name) {
                'b:constructor-arg'(value:'abc') {}
                'b:constructor-arg'(value:'def') {}
            }
            createAppContext()
        when:
            def hf = getFilter(HeaderWriterFilter)
            MockHttpServletResponse response = new MockHttpServletResponse()
            hf.doFilter(new MockHttpServletRequest(), response, new MockFilterChain())
        then:
             assertHeaders(response, ['abc':'def'])
    }

    def 'http headers header no name produces error'() {
        when:
        httpAutoConfig {
            'headers'() {
                'header'(value: 'b')
            }
        }
        createAppContext()

        then:
        thrown(BeanCreationException)
    }

    def 'http headers header no value produces error'() {
        when:
        httpAutoConfig {
            'headers'() {
                'header'(name: 'a')
            }
        }
        createAppContext()

        then:
        thrown(BeanCreationException)
    }

    def 'http headers xss-protection defaults'() {
        when:
        httpAutoConfig {
            'headers'() {
                'xss-protection'()
            }
        }
        createAppContext()

        def hf = getFilter(HeaderWriterFilter)
        MockHttpServletResponse response = new MockHttpServletResponse()
        hf.doFilter(new MockHttpServletRequest(), response, new MockFilterChain())

        then:
        assertHeaders(response, ['X-XSS-Protection':'1; mode=block'])
    }

    def 'http headers xss-protection enabled=true'() {
        when:
        httpAutoConfig {
            'headers'() {
                'xss-protection'(enabled:'true')
            }
        }
        createAppContext()

        def hf = getFilter(HeaderWriterFilter)
        MockHttpServletResponse response = new MockHttpServletResponse()
        hf.doFilter(new MockHttpServletRequest(), response, new MockFilterChain())

        then:
        assertHeaders(response, ['X-XSS-Protection':'1; mode=block'])
    }

    def 'http headers xss-protection enabled=false'() {
        when:
        httpAutoConfig {
            'headers'() {
                'xss-protection'(enabled:'false')
            }
        }
        createAppContext()

        def hf = getFilter(HeaderWriterFilter)
        MockHttpServletResponse response = new MockHttpServletResponse()
        hf.doFilter(new MockHttpServletRequest(), response, new MockFilterChain())

        then:
        assertHeaders(response, ['X-XSS-Protection':'0'])
    }

    def 'http headers xss-protection enabled=false and block=true produces error'() {
        when:
        httpAutoConfig {
            'headers'() {
                'xss-protection'(enabled:'false', block:'true')
            }
        }
        createAppContext()

        def hf = getFilter(HeaderWriterFilter)

        then:
        BeanCreationException e = thrown()
        e.message.contains 'Cannot set block to true with enabled false'
    }

    def 'http headers cache-control'() {
        setup:
            httpAutoConfig {
                'headers'() {
                    'cache-control'()
                }
            }
            createAppContext()
            def springSecurityFilterChain = appContext.getBean(FilterChainProxy)
            MockHttpServletResponse response = new MockHttpServletResponse()
        when:
            springSecurityFilterChain.doFilter(new MockHttpServletRequest(), response, new MockFilterChain())
        then:
            assertHeaders(response, ['Cache-Control': 'no-cache,no-store,max-age=0,must-revalidate','Pragma':'no-cache'])
    }

    def 'http headers hsts'() {
        setup:
            httpAutoConfig {
                'headers'() {
                    'hsts'()
                }
            }
            createAppContext()
            def springSecurityFilterChain = appContext.getBean(FilterChainProxy)
            MockHttpServletResponse response = new MockHttpServletResponse()
        when:
            springSecurityFilterChain.doFilter(new MockHttpServletRequest(secure:true), response, new MockFilterChain())
        then:
            assertHeaders(response, ['Strict-Transport-Security': 'max-age=31536000 ; includeSubDomains'])
    }

    def 'http headers hsts default only invokes on HttpServletRequest.isSecure = true'() {
        setup:
            httpAutoConfig {
                'headers'() {
                    'hsts'()
                }
            }
            createAppContext()
            def springSecurityFilterChain = appContext.getBean(FilterChainProxy)
            MockHttpServletResponse response = new MockHttpServletResponse()
        when:
            springSecurityFilterChain.doFilter(new MockHttpServletRequest(), response, new MockFilterChain())
        then:
            response.headerNames.empty
    }

    def 'http headers hsts custom'() {
        setup:
            httpAutoConfig {
                'headers'() {
                    'hsts'('max-age-seconds':'1','include-subdomains':false, 'request-matcher-ref' : 'matcher')
                }
            }

            xml.'b:bean'(id: 'matcher', 'class': AnyRequestMatcher.name)
            createAppContext()
            def springSecurityFilterChain = appContext.getBean(FilterChainProxy)
            MockHttpServletResponse response = new MockHttpServletResponse()
        when:
            springSecurityFilterChain.doFilter(new MockHttpServletRequest(), response, new MockFilterChain())
        then:
            assertHeaders(response, ['Strict-Transport-Security': 'max-age=1'])
    }

    def assertHeaders(MockHttpServletResponse response, Map<String,String> expected) {
        assert response.headerNames == expected.keySet()
        expected.each { headerName, value ->
            assert response.getHeaderValues(headerName) == value.split(',')
        }
    }
}
