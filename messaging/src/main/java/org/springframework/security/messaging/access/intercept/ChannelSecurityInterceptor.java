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
package org.springframework.security.messaging.access.intercept;

import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.MessageHeaders;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.security.access.SecurityMetadataSource;
import org.springframework.security.access.intercept.AbstractSecurityInterceptor;
import org.springframework.security.access.intercept.InterceptorStatusToken;
import org.springframework.security.messaging.access.expression.ExpressionBasedMessageSecurityMetadataSourceFactory;
import org.springframework.util.Assert;

/**
 * Performs security handling of Message resources via a ChannelInterceptor implementation.
 * <p>
 * The <code>SecurityMetadataSource</code> required by this security interceptor is of type {@link
 * MessageSecurityMetadataSource}.
 * </p>
 * <p>
 * Refer to {@link AbstractSecurityInterceptor} for details on the workflow.
 * </p>
 *
 * @see 4.0
 * @author Rob Winch
 */
public final class ChannelSecurityInterceptor extends AbstractSecurityInterceptor implements ChannelInterceptor {

    private final MessageSecurityMetadataSource metadataSource;

    /**
     * Creates a new instance
     *
     * @param metadataSource the MessageSecurityMetadataSource to use. Cannot be null.
     *
     * @see DefaultMessageSecurityMetadataSource
     * @see ExpressionBasedMessageSecurityMetadataSourceFactory
     */
    public ChannelSecurityInterceptor(MessageSecurityMetadataSource metadataSource) {
        Assert.notNull(metadataSource, "metadataSource cannot be null");
        this.metadataSource = metadataSource;
    }

    @Override
    public Class<?> getSecureObjectClass() {
        return Message.class;
    }

    @Override
    public SecurityMetadataSource obtainSecurityMetadataSource() {
        return metadataSource;
    }

    @Override
    public Message<?> preSend(Message<?> message, MessageChannel channel) {
        InterceptorStatusToken token = beforeInvocation(message);
        return token == null ? message : new TokenMessage(message,token);
    }

    @Override
    public void postSend(Message<?> message, MessageChannel channel, boolean sent) {
        if(!(message instanceof TokenMessage)) {
            // TODO What if other classes return another instance too?
            return;
        }
        InterceptorStatusToken token = ((TokenMessage)message).getToken();
        afterInvocation(token, null);
    }

    @Override
    public void afterSendCompletion(Message<?> message, MessageChannel channel, boolean sent, Exception ex) {
        if(!(message instanceof TokenMessage)) {
            // TODO What if other classes return another instance too?
            return;
        }
        InterceptorStatusToken token = ((TokenMessage)message).getToken();
        finallyInvocation(token);
    }

    public boolean preReceive(MessageChannel channel) {
        return true;
    }

    @Override
    public Message<?> postReceive(Message<?> message, MessageChannel channel) {
        return message;
    }

    @Override
    public void afterReceiveCompletion(Message<?> message, MessageChannel channel, Exception ex) {
    }

    static final class TokenMessage implements Message {
        private final Message delegate;
        private final InterceptorStatusToken token;

        TokenMessage(Message delegate, InterceptorStatusToken token) {
            this.delegate = delegate;
            this.token = token;
        }

        public InterceptorStatusToken getToken() {
            return token;
        }

        @Override
        public MessageHeaders getHeaders() {
            return delegate.getHeaders();
        }

        @Override
        public Object getPayload() {
            return delegate.getPayload();
        }
    }
}
