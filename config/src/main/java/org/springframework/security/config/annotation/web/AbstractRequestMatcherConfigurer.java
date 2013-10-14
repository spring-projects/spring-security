/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation.web;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.AbstractRequestMatcherMappingConfigurer;
import org.springframework.security.web.util.matchers.AntPathRequestMatcher;
import org.springframework.security.web.util.matchers.AnyRequestMatcher;
import org.springframework.security.web.util.matchers.RegexRequestMatcher;
import org.springframework.security.web.util.RequestMatcher;

/**
 * A base class for registering {@link RequestMatcher}'s. For example, it might allow for specifying which
 * {@link RequestMatcher} require a certain level of authorization.
 *
 *
 * @param <B> The Builder that is building Object O and is configured by this {@link AbstractRequestMatcherMappingConfigurer}
 * @param <C> The object that is returned or Chained after creating the RequestMatcher
 * @param <O> The Object being built by Builder B
 *
 * @author Rob Winch
 * @since 3.2
 */
public abstract class AbstractRequestMatcherConfigurer<B extends SecurityBuilder<O>,C,O> extends SecurityConfigurerAdapter<O,B> {
    private static final RequestMatcher ANY_REQUEST = AnyRequestMatcher.INSTANCE;
    /**
     * Maps any request.
     *
     * @param method the {@link HttpMethod} to use or {@code null} for any {@link HttpMethod}.
     * @param antPatterns the ant patterns to create {@link org.springframework.security.web.util.matchers.AntPathRequestMatcher}
     *                    from
     *
     * @return the object that is chained after creating the {@link RequestMatcher}
     */
    public C anyRequest() {
        return requestMatchers(ANY_REQUEST);
    }

    /**
     * Maps a {@link List} of {@link org.springframework.security.web.util.matchers.AntPathRequestMatcher} instances.
     *
     * @param method the {@link HttpMethod} to use or {@code null} for any {@link HttpMethod}.
     * @param antPatterns the ant patterns to create {@link org.springframework.security.web.util.matchers.AntPathRequestMatcher}
     *                    from
     *
     * @return the object that is chained after creating the {@link RequestMatcher}
     */
    public C antMatchers(HttpMethod method, String... antPatterns) {
        return chainRequestMatchers(RequestMatchers.antMatchers(method, antPatterns));
    }

    /**
     * Maps a {@link List} of {@link org.springframework.security.web.util.matchers.AntPathRequestMatcher} instances that do
     * not care which {@link HttpMethod} is used.
     *
     * @param antPatterns the ant patterns to create {@link org.springframework.security.web.util.matchers.AntPathRequestMatcher}
     *                    from
     *
     * @return the object that is chained after creating the {@link RequestMatcher}
     */
    public C antMatchers(String... antPatterns) {
        return chainRequestMatchers(RequestMatchers.antMatchers(antPatterns));
    }

    /**
     * Maps a {@link List} of {@link org.springframework.security.web.util.matchers.RegexRequestMatcher} instances.
     *
     * @param method the {@link HttpMethod} to use or {@code null} for any {@link HttpMethod}.
     * @param regexPatterns the regular expressions to create
     *                      {@link org.springframework.security.web.util.matchers.RegexRequestMatcher} from
     *
     * @return the object that is chained after creating the {@link RequestMatcher}
     */
    public C regexMatchers(HttpMethod method, String... regexPatterns) {
        return chainRequestMatchers(RequestMatchers.regexMatchers(method,
                regexPatterns));
    }

    /**
     * Create a {@link List} of {@link org.springframework.security.web.util.matchers.RegexRequestMatcher} instances that do not
     * specify an {@link HttpMethod}.
     *
     * @param regexPatterns the regular expressions to create
     *                      {@link org.springframework.security.web.util.matchers.RegexRequestMatcher} from
     *
     * @return the object that is chained after creating the {@link RequestMatcher}
     */
    public C regexMatchers(String... regexPatterns) {
        return chainRequestMatchers(RequestMatchers.regexMatchers(regexPatterns));
    }

    /**
     * Associates a list of {@link RequestMatcher} instances with the {@link AbstractRequestMatcherMappingConfigurer}
     *
     * @param requestMatchers the {@link RequestMatcher} instances
     *
     * @return the object that is chained after creating the {@link RequestMatcher}
     */
    public C requestMatchers(RequestMatcher... requestMatchers) {
        return chainRequestMatchers(Arrays.asList(requestMatchers));
    }

    /**
     * Subclasses should implement this method for returning the object that is chained to the creation of the
     * {@link RequestMatcher} instances.
     *
     * @param requestMatchers the {@link RequestMatcher} instances that were created
     * @return the chained Object for the subclass which allows association of something else to the
     *         {@link RequestMatcher}
     */
    protected abstract C chainRequestMatchers(List<RequestMatcher> requestMatchers);

    /**
     * Utilities for creating {@link RequestMatcher} instances.
     *
     * @author Rob Winch
     * @since 3.2
     */
    private static final class RequestMatchers {

        /**
         * Create a {@link List} of {@link AntPathRequestMatcher} instances.
         *
         * @param httpMethod the {@link HttpMethod} to use or {@code null} for any {@link HttpMethod}.
         * @param antPatterns the ant patterns to create {@link AntPathRequestMatcher} from
         *
         * @return a {@link List} of {@link AntPathRequestMatcher} instances
         */
        public static List<RequestMatcher> antMatchers(HttpMethod httpMethod, String...antPatterns) {
            String method = httpMethod == null ? null : httpMethod.toString();
            List<RequestMatcher> matchers = new ArrayList<RequestMatcher>();
            for(String pattern : antPatterns) {
                matchers.add(new AntPathRequestMatcher(pattern, method));
            }
            return matchers;
        }

        /**
         * Create a {@link List} of {@link AntPathRequestMatcher} instances that do not specify an {@link HttpMethod}.
         *
         * @param antPatterns the ant patterns to create {@link AntPathRequestMatcher} from
         *
         * @return a {@link List} of {@link AntPathRequestMatcher} instances
         */
        public static List<RequestMatcher> antMatchers(String...antPatterns) {
            return antMatchers(null, antPatterns);
        }

        /**
         * Create a {@link List} of {@link RegexRequestMatcher} instances.
         *
         * @param httpMethod the {@link HttpMethod} to use or {@code null} for any {@link HttpMethod}.
         * @param regexPatterns the regular expressions to create {@link RegexRequestMatcher} from
         *
         * @return a {@link List} of {@link RegexRequestMatcher} instances
         */
        public static List<RequestMatcher> regexMatchers(HttpMethod httpMethod, String...regexPatterns) {
            String method = httpMethod == null ? null : httpMethod.toString();
            List<RequestMatcher> matchers = new ArrayList<RequestMatcher>();
            for(String pattern : regexPatterns) {
                matchers.add(new RegexRequestMatcher(pattern, method));
            }
            return matchers;
        }

        /**
         * Create a {@link List} of {@link RegexRequestMatcher} instances that do not specify an {@link HttpMethod}.
         *
         *  @param regexPatterns the regular expressions to create {@link RegexRequestMatcher} from
         *
         * @return a {@link List} of {@link RegexRequestMatcher} instances
         */
        public static List<RequestMatcher> regexMatchers(String...regexPatterns) {
            return regexMatchers(null, regexPatterns);
        }

        private RequestMatchers() {}
    }
}
