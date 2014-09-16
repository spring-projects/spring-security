/*
 * Copyright 2002-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.messaging.util.matcher;

import org.springframework.messaging.Message;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.Assert;
import org.springframework.util.PathMatcher;

/**
 * <p>
 * MessageMatcher which compares a pre-defined pattern against the destination of a {@link Message}.
 * </p>
 *
 * @since 4.0
 * @author Rob Winch
 */
public final class SimpDestinationMessageMatcher implements MessageMatcher<Object> {
    private final PathMatcher matcher;
    private final String pattern;

    /**
     * <p>
     * Creates a new instance with the specified pattern and a {@link AntPathMatcher} created from the default
     * constructor.
     * </p>
     *
     * @param pattern the pattern to use
     * @param pathMatcher the {@link PathMatcher} to use.
     */
    public SimpDestinationMessageMatcher(String pattern, PathMatcher pathMatcher) {
        Assert.notNull(pattern, "pattern cannot be null");
        Assert.notNull(pathMatcher, "pathMatcher cannot be null");
        this.matcher = pathMatcher;
        this.pattern = pattern;
    }

    /**
     * <p>
     * Creates a new instance with the specified pattern and a {@link AntPathMatcher} created from the default
     * constructor.
     * </p>
     *
     * <p>The mapping matches destinations using the following rules:
     *
     * <ul>
     * <li>? matches one character</li>
     * <li>* matches zero or more characters</li>
     * <li>** matches zero or more 'directories' in a path</li>
     * </ul>
     *
     * <p>Some examples:
     *
     * <ul>
     * <li>{@code com/t?st.jsp} - matches {@code com/test} but also
     * {@code com/tast} or {@code com/txst}</li>
     * <li>{@code com/*suffix} - matches all files ending in {@code suffix} in the {@code com} directory</li>
     * <li>{@code com/&#42;&#42;/test} - matches all destinations ending with {@code test} underneath the {@code com} path</li>
     * </ul>
     *
     * @param pattern the pattern to use
     */
    public SimpDestinationMessageMatcher(String pattern) {
        this(pattern, new AntPathMatcher());
    }

    public boolean matches(Message<? extends Object> message) {
        String destination = SimpMessageHeaderAccessor.getDestination(message.getHeaders());
        return destination != null && matcher.match(pattern, destination);
    }
}