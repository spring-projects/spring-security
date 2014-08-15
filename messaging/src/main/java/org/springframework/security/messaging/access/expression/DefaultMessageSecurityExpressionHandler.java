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
package org.springframework.security.messaging.access.expression;

import org.springframework.messaging.Message;
import org.springframework.security.access.expression.AbstractSecurityExpressionHandler;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.expression.SecurityExpressionOperations;
import org.springframework.security.core.Authentication;

/**
 * The default implementation of {@link SecurityExpressionHandler} which uses a {@link MessageSecurityExpressionRoot}.
 *
 * @since 4.0
 *
 * @author Rob Winch
 */
public class DefaultMessageSecurityExpressionHandler<T> extends AbstractSecurityExpressionHandler<Message<T>> {

    @Override
    protected SecurityExpressionOperations createSecurityExpressionRoot(Authentication authentication, Message<T> invocation) {
        return new MessageSecurityExpressionRoot(authentication,invocation);
    }
}
