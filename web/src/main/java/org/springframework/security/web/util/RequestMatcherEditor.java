/*
 * Copyright 2010 the original author or authors.
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

package org.springframework.security.web.util;

import java.beans.PropertyEditorSupport;

import org.springframework.security.web.util.matchers.ELRequestMatcher;
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint;

/**
 * PropertyEditor which creates ELRequestMatcher instances from Strings
 *
 * This allows to use a String in a BeanDefinition instead of an (inner) bean
 * if a RequestMatcher is required, e.g. in {@link DelegatingAuthenticationEntryPoint}
 *
 * @author Mike Wiesner
 * @since 3.0.2
 */
public class RequestMatcherEditor extends PropertyEditorSupport {

    @Override
    public void setAsText(String text) throws IllegalArgumentException {
        setValue(new ELRequestMatcher(text));
    }

}
