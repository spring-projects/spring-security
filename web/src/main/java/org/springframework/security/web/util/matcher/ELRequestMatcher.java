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

package org.springframework.security.web.util.matcher;

import javax.servlet.http.HttpServletRequest;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * A RequestMatcher implementation which uses a SpEL expression
 *
 * <p>With the default EvaluationContext ({@link ELRequestMatcherContext}) you can use
 * <code>hasIpAdress()</code> and <code>hasHeader()</code></p>
 *
 * <p>See {@link DelegatingAuthenticationEntryPoint} for an example configuration.</p>
 *
 *
 * @author Mike Wiesner
 * @since 3.0.2
 */
public class ELRequestMatcher implements RequestMatcher {

    private final Expression expression;

    public ELRequestMatcher(String el) {
        SpelExpressionParser parser = new SpelExpressionParser();
        expression = parser.parseExpression(el);
    }

    public boolean matches(HttpServletRequest request) {
        EvaluationContext context = createELContext(request);
        return expression.getValue(context, Boolean.class).booleanValue();
    }

    /**
     * Subclasses can override this methode if they want to use a different EL root context
     *
     * @return EL root context which is used to evaluate the expression
     */
    public EvaluationContext createELContext(HttpServletRequest request) {
        return new StandardEvaluationContext(new ELRequestMatcherContext(request));
    }

}
