/* Copyright 2004, 2005 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.acegisecurity.adapters;

import org.acegisecurity.AcegiMessageSource;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.BadCredentialsException;

import org.acegisecurity.providers.AuthenticationProvider;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;

import org.springframework.util.Assert;


/**
 * An {@link AuthenticationProvider} implementation that can authenticate an
 * {@link AuthByAdapter}.
 * 
 * <P>
 * Configured in the bean context with a key that should match the key used by
 * adapters to generate <code>AuthByAdapter</code> instances. It treats as
 * valid any such instance presenting a hash code that matches the
 * <code>AuthByAdapterProvider</code>-configured key.
 * </p>
 * 
 * <P>
 * If the key does not match, a <code>BadCredentialsException</code> is thrown.
 * </p>
 */
public class AuthByAdapterProvider implements InitializingBean,
    AuthenticationProvider, MessageSourceAware {
    //~ Instance fields ========================================================

    protected MessageSourceAccessor messages = AcegiMessageSource.getAccessor();
    private String key;

    //~ Methods ================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(key,
            "A Key is required and should match that configured for the adapters");
        Assert.notNull(messages, "A message source must be set");
    }

    public Authentication authenticate(Authentication authentication)
        throws AuthenticationException {
        AuthByAdapter token = (AuthByAdapter) authentication;

        if (token.getKeyHash() == key.hashCode()) {
            return authentication;
        } else {
            throw new BadCredentialsException(messages.getMessage(
                    "AuthByAdapterProvider.incorrectKey",
                    "The presented AuthByAdapter implementation does not contain the expected key"));
        }
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public void setMessageSource(MessageSource messageSource) {
        this.messages = new MessageSourceAccessor(messageSource);
    }

    public boolean supports(Class authentication) {
        if (AuthByAdapter.class.isAssignableFrom(authentication)) {
            return true;
        } else {
            return false;
        }
    }
}
