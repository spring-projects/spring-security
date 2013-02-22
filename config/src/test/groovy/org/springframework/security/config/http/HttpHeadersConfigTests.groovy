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

import org.springframework.security.util.FieldUtils

import javax.servlet.Filter
import javax.servlet.http.HttpServletRequest

import org.springframework.beans.factory.parsing.BeanDefinitionParsingException
import org.springframework.beans.factory.xml.XmlBeanDefinitionStoreException;
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.config.BeanIds
import org.springframework.security.openid.OpenIDAuthenticationFilter
import org.springframework.security.openid.OpenIDAuthenticationToken
import org.springframework.security.openid.OpenIDConsumer
import org.springframework.security.openid.OpenIDConsumerException
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter
import org.springframework.security.web.headers.HeadersFilter

/**
 *
 * @author Rob Winch
 */
class HttpHeadersConfigTests extends AbstractHttpConfigTests {

    def 'no http headers filter'() {
        httpAutoConfig {
        }
        createAppContext()

        def hf = getFilter(HeadersFilter)

        expect:
        !hf
    }

    def 'http headers with empty headers'() {
        httpAutoConfig {
            'headers'()
        }
        createAppContext()

        def hf = getFilter(HeadersFilter)
        MockHttpServletResponse response = new MockHttpServletResponse();
        hf.doFilter(new MockHttpServletRequest(), response);

        expect:
        hf
        response.headers.isEmpty()
    }

    def 'http headers content-type-options'() {
        httpAutoConfig {
            'headers'() {
                'content-type-options'()
            }
        }
        createAppContext()

        def hf = getFilter(HeadersFilter)
        MockHttpServletResponse response = new MockHttpServletResponse();
        hf.doFilter(new MockHttpServletRequest(), response);
        expect:
        hf
        response.headers == ['X-Content-Type-Options':'nosniff']
    }

    def 'http headers frame-options defaults to DENY'() {
        httpAutoConfig {
            'headers'() {
                'frame-options'()
            }
        }
        createAppContext()

        def hf = getFilter(HeadersFilter)

        expect:
        hf
        hf.headers == ['X-Frame-Options':'DENY']
    }

    def 'http headers frame-options DENY'() {
        httpAutoConfig {
            'headers'() {
                'frame-options'(policy : 'DENY')
            }
        }
        createAppContext()

        def hf = getFilter(HeadersFilter)

        expect:
        hf
        hf.headers == ['X-Frame-Options':'DENY']
    }

    def 'http headers frame-options SAMEORIGIN'() {
        httpAutoConfig {
            'headers'() {
                'frame-options'(policy : 'SAMEORIGIN')
            }
        }
        createAppContext()

        def hf = getFilter(HeadersFilter)

        expect:
        hf
        hf.headers == ['X-Frame-Options':'SAMEORIGIN']
    }

    def 'http headers frame-options ALLOW-FROM no origin reports error'() {
        when:
        httpAutoConfig {
            'headers'() {
                'frame-options'(policy : 'ALLOW-FROM')
            }
        }
        createAppContext()

        def hf = getFilter(HeadersFilter)

        then:
        BeanDefinitionParsingException e = thrown()
        e.message.contains '<frame-options policy="ALLOW-FROM"/> requires a non-empty string value for the origin attribute to be specified.'
    }

    def 'http headers frame-options ALLOW-FROM spaces only origin reports error'() {
        when:
        httpAutoConfig {
            'headers'() {
                'frame-options'(policy : 'ALLOW-FROM', origin : ' ')
            }
        }
        createAppContext()

        def hf = getFilter(HeadersFilter)

        then:
        BeanDefinitionParsingException e = thrown()
        e.message.contains '<frame-options policy="ALLOW-FROM"/> requires a non-empty string value for the origin attribute to be specified.'
    }

    def 'http headers frame-options ALLOW-FROM'() {
        when:
        httpAutoConfig {
            'headers'() {
                'frame-options'(policy : 'ALLOW-FROM', origin : 'https://example.com')
            }
        }
        createAppContext()

        def hf = getFilter(HeadersFilter)

        then:
        hf
        hf.headers == ['X-Frame-Options':'ALLOW-FROM https://example.com']
    }

    def 'http headers header a=b'() {
        when:
        httpAutoConfig {
            'headers'() {
                'header'(name : 'a', value: 'b')
            }
        }
        createAppContext()

        def hf = getFilter(HeadersFilter)

        then:
        hf
        hf.headers == ['a':'b']
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

        def hf = getFilter(HeadersFilter)

        then:
        hf
        hf.headers.sort() == ['a':'b', 'c':'d'].sort()
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
        thrown(XmlBeanDefinitionStoreException)
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
        thrown(XmlBeanDefinitionStoreException)
    }

    def 'http headers xss-protection defaults'() {
        when:
        httpAutoConfig {
            'headers'() {
                'xss-protection'()
            }
        }
        createAppContext()

        def hf = getFilter(HeadersFilter)

        then:
        hf
        hf.headers == ['X-XSS-Protection':'1; mode=block']
    }

    def 'http headers xss-protection enabled=true'() {
        when:
        httpAutoConfig {
            'headers'() {
                'xss-protection'(enabled:'true')
            }
        }
        createAppContext()

        def hf = getFilter(HeadersFilter)

        then:
        hf
        hf.headers == ['X-XSS-Protection':'1; mode=block']
    }

    def 'http headers xss-protection enabled=false'() {
        when:
        httpAutoConfig {
            'headers'() {
                'xss-protection'(enabled:'false')
            }
        }
        createAppContext()

        def hf = getFilter(HeadersFilter)

        then:
        hf
        hf.headers == ['X-XSS-Protection':'0']
    }

    def 'http headers xss-protection enabled=false and block=true produces error'() {
        when:
        httpAutoConfig {
            'headers'() {
                'xss-protection'(enabled:'false', block:'true')
            }
        }
        createAppContext()

        def hf = getFilter(HeadersFilter)

        then:
        BeanDefinitionParsingException e = thrown()
        e.message.contains '<xss-protection enabled="false"/> does not allow block="true".'
    }
}
