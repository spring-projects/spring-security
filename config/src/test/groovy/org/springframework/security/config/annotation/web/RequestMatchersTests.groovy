/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation.web;

import static org.springframework.security.config.annotation.web.AbstractRequestMatcherRegistry.RequestMatchers.*

import org.springframework.http.HttpMethod;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;

import spock.lang.Specification;

/**
 * @author Rob Winch
 *
 */
class RequestMatchersTests extends Specification {

    def "regexMatchers(GET,'/a.*') uses RegexRequestMatcher"() {
        when:
        def matchers = regexMatchers(HttpMethod.GET, "/a.*")
        then: 'matcher is a RegexRequestMatcher'
        matchers.collect {it.class } == [RegexRequestMatcher]
    }

    def "regexMatchers('/a.*') uses RegexRequestMatcher"() {
        when:
        def matchers = regexMatchers("/a.*")
        then: 'matcher is a RegexRequestMatcher'
        matchers.collect {it.class } == [RegexRequestMatcher]
    }

    def "antMatchers(GET,'/a.*') uses AntPathRequestMatcher"() {
        when:
        def matchers = antMatchers(HttpMethod.GET, "/a.*")
        then: 'matcher is a RegexRequestMatcher'
        matchers.collect {it.class } == [AntPathRequestMatcher]
    }

    def "antMatchers('/a.*') uses AntPathRequestMatcher"() {
        when:
        def matchers = antMatchers("/a.*")
        then: 'matcher is a AntPathRequestMatcher'
        matchers.collect {it.class } == [AntPathRequestMatcher]
    }
}
