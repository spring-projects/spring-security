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
package org.springframework.security.messaging.context;

import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.MessageHandler;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.support.ChannelInterceptorAdapter;
import org.springframework.messaging.support.ExecutorChannelInterceptor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;

/**
 * <p>
 * Creates a {@link ExecutorChannelInterceptor} that will obtain the {@link Authentication} from the specified
 * {@link Message#getHeaders()}.
 * </p>
 *
 * @since 4.0
 * @author Rob Winch
 */
public final class SecurityContextChannelInterceptor extends ChannelInterceptorAdapter implements ExecutorChannelInterceptor {
    private final SecurityContext EMPTY_CONTEXT = SecurityContextHolder.createEmptyContext();
    private static final ThreadLocal<SecurityContext> ORIGINAL_CONTEXT = new ThreadLocal<SecurityContext>();

    private final String authenticationHeaderName;

    /**
     * Creates a new instance using the header of the name {@link SimpMessageHeaderAccessor#USER_HEADER}.
     */
    public SecurityContextChannelInterceptor() {
        this(SimpMessageHeaderAccessor.USER_HEADER);
    }

    /**
     * Creates a new instance that uses the specified header to obtain the {@link Authentication}.
     *
     * @param authenticationHeaderName the header name to obtain the {@link Authentication}. Cannot be null.
     */
    public SecurityContextChannelInterceptor(String authenticationHeaderName) {
        Assert.notNull(authenticationHeaderName, "authenticationHeaderName cannot be null");
        this.authenticationHeaderName = authenticationHeaderName;
    }
    @Override
    public Message<?> preSend(Message<?> message, MessageChannel channel) {
        setup(message);
        return message;
    }

    @Override
    public void afterSendCompletion(Message<?> message, MessageChannel channel, boolean sent, Exception ex) {
        cleanup();
    }

    public Message<?> beforeHandle(Message<?> message, MessageChannel channel, MessageHandler handler) {
        setup(message);
        return message;
    }

    public void afterMessageHandled(Message<?> message, MessageChannel channel, MessageHandler handler, Exception ex) {
        cleanup();
    }

    private void setup(Message<?> message) {
        SecurityContext currentContext = SecurityContextHolder.getContext();
        ORIGINAL_CONTEXT.set(currentContext);

        Object user = message.getHeaders().get(authenticationHeaderName);
        if(!(user instanceof Authentication)) {
            return;
        }
        Authentication authentication = (Authentication) user;
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
    }

    private void cleanup() {
        SecurityContext originalContext = ORIGINAL_CONTEXT.get();
        ORIGINAL_CONTEXT.remove();

        try {
            if(EMPTY_CONTEXT.equals(originalContext)) {
                SecurityContextHolder.clearContext();
            } else {
                SecurityContextHolder.setContext(originalContext);
            }
        } catch(Throwable t) {
            SecurityContextHolder.clearContext();
        }
    }
}
