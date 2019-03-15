/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.config.http

import org.springframework.beans.factory.BeanCreationException
import org.springframework.beans.factory.parsing.BeanDefinitionParsingException
import org.springframework.beans.factory.xml.XmlBeanDefinitionStoreException
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.web.FilterChainProxy
import org.springframework.security.web.header.HeaderWriterFilter
import org.springframework.security.web.header.writers.StaticHeadersWriter
import org.springframework.security.web.util.matcher.AnyRequestMatcher

/**
 *
 * @author Rob Winch
 * @author Tim Ysewyn
 */
class HttpHeadersConfigTests extends AbstractHttpConfigTests {
	def defaultHeaders = ['X-Content-Type-Options':'nosniff',
								'X-Frame-Options':'DENY',
								'Strict-Transport-Security': 'max-age=31536000 ; includeSubDomains',
								'Cache-Control': 'no-cache, no-store, max-age=0, must-revalidate',
								'Expires' : '0',
								'Pragma':'no-cache',
								'X-XSS-Protection' : '1; mode=block']
	def 'headers disabled'() {
		setup:
			httpAutoConfig {
				'headers'(disabled:true)
			}
			createAppContext()

		when:
			def hf = getFilter(HeaderWriterFilter)
		then:
			!hf
	}

	def 'headers disabled with child fails'() {
		when:
			httpAutoConfig {
				'headers'(disabled:true) {
					'content-type-options'()
				}
			}
			createAppContext()
		then:
			thrown(BeanDefinitionParsingException)
	}

	def 'default headers'() {
		httpAutoConfig {
		}
		createAppContext()

		when:
			def hf = getFilter(HeaderWriterFilter)
			MockHttpServletResponse response = new MockHttpServletResponse()
			hf.doFilter(new MockHttpServletRequest(secure:true), response, new MockFilterChain())
		then:
			assertHeaders(response, defaultHeaders)
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
			assertHeaders(response, defaultHeaders)
	}

	def 'http headers frame-options@policy=SAMEORIGIN with defaults'() {
		httpAutoConfig {
			'headers'() {
				'frame-options'(policy:'SAMEORIGIN')
			}
		}
		createAppContext()

		def hf = getFilter(HeaderWriterFilter)
		MockHttpServletResponse response = new MockHttpServletResponse()
		hf.doFilter(new MockHttpServletRequest(secure:true), response, new MockFilterChain())
		def expectedHeaders = [:] << defaultHeaders
		expectedHeaders['X-Frame-Options'] = 'SAMEORIGIN'

		expect:
		assertHeaders(response, expectedHeaders)
	}


	// --- defaults disabled

	def 'http headers content-type-options'() {
		httpAutoConfig {
			'headers'('defaults-disabled':true) {
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
			'headers'('defaults-disabled':true) {
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
			'headers'('defaults-disabled':true) {
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
			'headers'('defaults-disabled':true) {
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
			'headers'('defaults-disabled':true) {
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
			'headers'('defaults-disabled':true) {
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
			'headers'('defaults-disabled':true) {
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

	def 'http headers frame-options ALLOW-FROM with whitelist strategy'() {
		when:
		httpAutoConfig {
			'headers'('defaults-disabled':true) {
				'frame-options'(policy : 'ALLOW-FROM', strategy: 'whitelist', value : 'https://example.com')
			}
		}
		createAppContext()

		def hf = getFilter(HeaderWriterFilter)
		MockHttpServletResponse response = new MockHttpServletResponse()

		def request = new MockHttpServletRequest()
		request.setParameter("from", "https://example.com");
		hf.doFilter(request, response, new MockFilterChain())

		then:
		assertHeaders(response, ['X-Frame-Options':'ALLOW-FROM https://example.com'])
	}

	def 'http headers header a=b'() {
		when:
		httpAutoConfig {
			'headers'('defaults-disabled':true) {
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
			'headers'('defaults-disabled':true) {
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
				'headers'('defaults-disabled':true) {
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
			'headers'('defaults-disabled':true) {
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
			'headers'('defaults-disabled':true) {
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
			'headers'('defaults-disabled':true) {
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
			'headers'('defaults-disabled':true) {
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
			'headers'('defaults-disabled':true) {
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
			'headers'('defaults-disabled':true) {
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
				'headers'('defaults-disabled':true) {
					'cache-control'()
				}
			}
			createAppContext()
			def springSecurityFilterChain = appContext.getBean(FilterChainProxy)
			MockHttpServletResponse response = new MockHttpServletResponse()
		when:
			springSecurityFilterChain.doFilter(new MockHttpServletRequest(), response, new MockFilterChain())
		then:
			assertHeaders(response, ['Cache-Control': 'no-cache, no-store, max-age=0, must-revalidate',
									'Expires' : '0',
									'Pragma':'no-cache'])
	}

	def 'http headers hsts'() {
		setup:
			httpAutoConfig {
				'headers'('defaults-disabled':true) {
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
				'headers'('defaults-disabled':true) {
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
				'headers'('defaults-disabled':true) {
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

		def 'http headers hpkp no pins'() {
				setup:
						httpAutoConfig {
								'headers'('defaults-disabled':true) {
										'hpkp'()
								}
						}
				when:
						createAppContext()
				then:
						XmlBeanDefinitionStoreException expected = thrown()
						expected.message.contains 'The content of element \'hpkp\' is not complete'
		}

		def 'http headers hpkp no pin'() {
				setup:
						httpAutoConfig {
								'headers'('defaults-disabled':true) {
										'hpkp'() {
												'pins'()
										}
								}
						}
				when:
						createAppContext()
				then:
						XmlBeanDefinitionStoreException expected = thrown()
						expected.message.contains 'The content of element \'pins\' is not complete'
		}

	def 'http headers hpkp'() {
		setup:
			httpAutoConfig {
				'headers'('defaults-disabled':true) {
					'hpkp'() {
						'pins'() {
							'pin'('algorithm':'sha256', 'd6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=')
						}
					}
				}
			}
			createAppContext()
			def springSecurityFilterChain = appContext.getBean(FilterChainProxy)
			MockHttpServletResponse response = new MockHttpServletResponse()
		when:
			springSecurityFilterChain.doFilter(new MockHttpServletRequest(secure:true), response, new MockFilterChain())
		then:
			assertHeaders(response, ['Public-Key-Pins-Report-Only': 'max-age=5184000 ; pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM="'])
	}

		def 'http headers hpkp with default algorithm'() {
				setup:
						httpAutoConfig {
								'headers'('defaults-disabled':true) {
										'hpkp'() {
												'pins'() {
														'pin'('d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=')
												}
										}
								}
						}
						createAppContext()
						def springSecurityFilterChain = appContext.getBean(FilterChainProxy)
						MockHttpServletResponse response = new MockHttpServletResponse()
				when:
						springSecurityFilterChain.doFilter(new MockHttpServletRequest(secure:true), response, new MockFilterChain())
				then:
						assertHeaders(response, ['Public-Key-Pins-Report-Only': 'max-age=5184000 ; pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM="'])
		}

	def 'http headers hpkp only invokes on HttpServletRequest.isSecure = true'() {
		setup:
						httpAutoConfig {
								'headers'('defaults-disabled':true) {
										'hpkp'() {
												'pins'() {
														'pin'('algorithm':'sha256', 'E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=')
												}
										}
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

		def 'http headers hpkp with custom max age'() {
				setup:
						httpAutoConfig {
								'headers'('defaults-disabled':true) {
										'hpkp'('max-age-seconds':'604800') {
												'pins'() {
														'pin'('algorithm':'sha256', 'd6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=')
												}
										}
								}
						}
						createAppContext()
						def springSecurityFilterChain = appContext.getBean(FilterChainProxy)
						MockHttpServletResponse response = new MockHttpServletResponse()
				when:
						springSecurityFilterChain.doFilter(new MockHttpServletRequest(secure:true), response, new MockFilterChain())
				then:
						assertHeaders(response, ['Public-Key-Pins-Report-Only': 'max-age=604800 ; pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM="'])
		}

		def 'http headers hpkp@reportOnly=false'() {
				setup:
						httpAutoConfig {
								'headers'('defaults-disabled':true) {
										'hpkp'('report-only':'false') {
												'pins'() {
														'pin'('algorithm':'sha256', 'E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=')
												}
										}
								}
						}
						createAppContext()
						def springSecurityFilterChain = appContext.getBean(FilterChainProxy)
						MockHttpServletResponse response = new MockHttpServletResponse()
				when:
						springSecurityFilterChain.doFilter(new MockHttpServletRequest(secure: true), response, new MockFilterChain())
				then:
						assertHeaders(response, ['Public-Key-Pins': 'max-age=5184000 ; pin-sha256="E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g="'])
		}

		def 'http headers hpkp@includeSubDomains=true'() {
				setup:
						httpAutoConfig {
								'headers'('defaults-disabled':true) {
										'hpkp'('include-subdomains':'true') {
												'pins'() {
														'pin'('algorithm':'sha256', 'E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=')
												}
										}
								}
						}
						createAppContext()
						def springSecurityFilterChain = appContext.getBean(FilterChainProxy)
						MockHttpServletResponse response = new MockHttpServletResponse()
				when:
						springSecurityFilterChain.doFilter(new MockHttpServletRequest(secure: true), response, new MockFilterChain())
				then:
						assertHeaders(response, ['Public-Key-Pins-Report-Only': 'max-age=5184000 ; pin-sha256="E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=" ; includeSubDomains'])
		}

		def 'http headers hpkp with report-uri'() {
				setup:
						httpAutoConfig {
								'headers'('defaults-disabled':true) {
										'hpkp'('report-uri':'http://example.net/pkp-report') {
												'pins'() {
														'pin'('algorithm':'sha256', 'E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=')
												}
										}
								}
						}
						createAppContext()
						def springSecurityFilterChain = appContext.getBean(FilterChainProxy)
						MockHttpServletResponse response = new MockHttpServletResponse()
				when:
						springSecurityFilterChain.doFilter(new MockHttpServletRequest(secure: true), response, new MockFilterChain())
				then:
						assertHeaders(response, ['Public-Key-Pins-Report-Only': 'max-age=5184000 ; pin-sha256="E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=" ; report-uri="http://example.net/pkp-report"'])
		}

	// --- disable single default header ---

	def 'http headers cache-controls@disabled=true'() {
		setup:
			httpAutoConfig {
				'headers'() {
					'cache-control'(disabled:true)
				}
			}
			createAppContext()
			def springSecurityFilterChain = appContext.getBean(FilterChainProxy)
			MockHttpServletResponse response = new MockHttpServletResponse()
			def expectedHeaders = [:] << defaultHeaders
			expectedHeaders.remove('Cache-Control')
			expectedHeaders.remove('Expires')
			expectedHeaders.remove('Pragma')
		when:
			springSecurityFilterChain.doFilter(new MockHttpServletRequest(secure:true), response, new MockFilterChain())
		then:
			assertHeaders(response, expectedHeaders)
	}

	def 'http headers content-type-options@disabled=true'() {
		setup:
			httpAutoConfig {
				'headers'() {
					'content-type-options'(disabled:true)
				}
			}
			createAppContext()
			def springSecurityFilterChain = appContext.getBean(FilterChainProxy)
			MockHttpServletResponse response = new MockHttpServletResponse()
			def expectedHeaders = [:] << defaultHeaders
			expectedHeaders.remove('X-Content-Type-Options')
		when:
			springSecurityFilterChain.doFilter(new MockHttpServletRequest(secure:true), response, new MockFilterChain())
		then:
			assertHeaders(response, expectedHeaders)
	}

	def 'http headers hsts@disabled=true'() {
		setup:
			httpAutoConfig {
				'headers'() {
					'hsts'(disabled:true)
				}
			}
			createAppContext()
			def springSecurityFilterChain = appContext.getBean(FilterChainProxy)
			MockHttpServletResponse response = new MockHttpServletResponse()
			def expectedHeaders = [:] << defaultHeaders
			expectedHeaders.remove('Strict-Transport-Security')
		when:
			springSecurityFilterChain.doFilter(new MockHttpServletRequest(), response, new MockFilterChain())
		then:
			assertHeaders(response, expectedHeaders)
	}

	def 'http headers hpkp@disabled=true'() {
		setup:
						httpAutoConfig {
								'headers'() {
										'hpkp'(disabled:true) {
												'pins'() {
														'pin'('algorithm':'sha256', 'E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=')
												}
										}
								}
						}
						createAppContext()
						def springSecurityFilterChain = appContext.getBean(FilterChainProxy)
						MockHttpServletResponse response = new MockHttpServletResponse()
						def expectedHeaders = [:] << defaultHeaders
		when:
				springSecurityFilterChain.doFilter(new MockHttpServletRequest(secure:true), response, new MockFilterChain())
		then:
				assertHeaders(response, expectedHeaders)
	}

	def 'http headers frame-options@disabled=true'() {
		setup:
			httpAutoConfig {
				'headers'() {
					'frame-options'(disabled:true)
				}
			}
			createAppContext()
			def springSecurityFilterChain = appContext.getBean(FilterChainProxy)
			MockHttpServletResponse response = new MockHttpServletResponse()
			def expectedHeaders = [:] << defaultHeaders
			expectedHeaders.remove('X-Frame-Options')
		when:
			springSecurityFilterChain.doFilter(new MockHttpServletRequest(secure:true), response, new MockFilterChain())
		then:
			assertHeaders(response, expectedHeaders)
	}

	def 'http headers xss-protection@disabled=true'() {
		setup:
			httpAutoConfig {
				'headers'() {
					'xss-protection'(disabled:true)
				}
			}
			createAppContext()
			def springSecurityFilterChain = appContext.getBean(FilterChainProxy)
			MockHttpServletResponse response = new MockHttpServletResponse()
			def expectedHeaders = [:] << defaultHeaders
			expectedHeaders.remove('X-XSS-Protection')
		when:
			springSecurityFilterChain.doFilter(new MockHttpServletRequest(secure:true), response, new MockFilterChain())
		then:
			assertHeaders(response, expectedHeaders)
	}

	// --- disable error handling ---

	def 'http headers hsts@disabled=true no include-subdomains'() {
		setup:
			httpAutoConfig {
				'headers'() {
					'hsts'(disabled:true,'include-subdomains':true)
				}
			}
		when:
			createAppContext()
		then:
			BeanDefinitionParsingException expected = thrown()
			expected.message.contains 'include-subdomains'
	}

	def 'http headers hsts@disabled=true no max-age'() {
		setup:
			httpAutoConfig {
				'headers'() {
					'hsts'(disabled:true,'max-age-seconds':123)
				}
			}
		when:
			createAppContext()
		then:
			BeanDefinitionParsingException expected = thrown()
			expected.message.contains 'max-age'
	}

	def 'http headers hsts@disabled=true no matcher-ref'() {
		setup:
			httpAutoConfig {
				'headers'() {
					'hsts'(disabled:true,'request-matcher-ref':'matcher')
				}
			}
			xml.'b:bean'(id: 'matcher', 'class': AnyRequestMatcher.name)
		when:
			createAppContext()
		then:
			BeanDefinitionParsingException expected = thrown()
			expected.message.contains 'request-matcher-ref'
	}

	def 'http xss@disabled=true no enabled'() {
		setup:
			httpAutoConfig {
				'headers'() {
					'xss-protection'(disabled:true,'enabled':true)
				}
			}
		when:
			createAppContext()
		then:
			BeanDefinitionParsingException expected = thrown()
			expected.message.contains 'enabled'
	}

	def 'http xss@disabled=true no block'() {
		setup:
			httpAutoConfig {
				'headers'() {
					'xss-protection'(disabled:true,'block':true)
				}
			}
		when:
			createAppContext()
		then:
			BeanDefinitionParsingException expected = thrown()
			expected.message.contains 'block'
	}

	def 'http frame-options@disabled=true no policy'() {
		setup:
			httpAutoConfig {
				'headers'() {
					'frame-options'(disabled:true,'policy':'DENY')
				}
			}
		when:
			createAppContext()
		then:
			BeanDefinitionParsingException expected = thrown()
			expected.message.contains 'policy'
	}

	def 'http headers defaults : content-security-policy'() {
		setup:
			httpAutoConfig {
				'headers'() {
					'content-security-policy'('policy-directives':'default-src \'self\'')
				}
			}
			createAppContext()
		when:
			def hf = getFilter(HeaderWriterFilter)
			MockHttpServletResponse response = new MockHttpServletResponse()
			hf.doFilter(new MockHttpServletRequest(secure:true), response, new MockFilterChain())
			def expectedHeaders = [:] << defaultHeaders
			expectedHeaders['Content-Security-Policy'] = 'default-src \'self\''
		then:
			assertHeaders(response, expectedHeaders)
	}

	def 'http headers disabled : content-security-policy not included'() {
		setup:
			httpAutoConfig {
				'headers'(disabled:true) {
					'content-security-policy'('policy-directives':'default-src \'self\'')
				}
			}
			createAppContext()
		when:
			def hf = getFilter(HeaderWriterFilter)
		then:
			!hf
	}

	def 'http headers defaults disabled : content-security-policy only'() {
		setup:
			httpAutoConfig {
				'headers'('defaults-disabled':true) {
					'content-security-policy'('policy-directives':'default-src \'self\'')
				}
			}
			createAppContext()
		when:
			def hf = getFilter(HeaderWriterFilter)
			MockHttpServletResponse response = new MockHttpServletResponse()
			hf.doFilter(new MockHttpServletRequest(secure:true), response, new MockFilterChain())
		then:
			assertHeaders(response, ['Content-Security-Policy':'default-src \'self\''])
	}

	def 'http headers defaults : content-security-policy with empty directives'() {
		when:
			httpAutoConfig {
				'headers'() {
					'content-security-policy'('policy-directives':'')
				}
			}
			createAppContext()
		then:
			thrown(BeanDefinitionParsingException)
	}

	def 'http headers defaults : content-security-policy report-only=true'() {
		setup:
			httpAutoConfig {
				'headers'() {
					'content-security-policy'('policy-directives':'default-src https:; report-uri https://example.com/', 'report-only':true)
				}
			}
			createAppContext()
		when:
			def hf = getFilter(HeaderWriterFilter)
			MockHttpServletResponse response = new MockHttpServletResponse()
			hf.doFilter(new MockHttpServletRequest(secure:true), response, new MockFilterChain())
			def expectedHeaders = [:] << defaultHeaders
			expectedHeaders['Content-Security-Policy-Report-Only'] = 'default-src https:; report-uri https://example.com/'
		then:
			assertHeaders(response, expectedHeaders)
	}

	def assertHeaders(MockHttpServletResponse response, Map<String,String> expected) {
		assert response.headerNames == expected.keySet()
		expected.each { headerName, value ->
			assert response.getHeaderValues(headerName) == [value]
		}
	}
}
