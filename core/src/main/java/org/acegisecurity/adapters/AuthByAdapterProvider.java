/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.adapters;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationException;
import net.sf.acegisecurity.BadCredentialsException;
import net.sf.acegisecurity.providers.AuthenticationProvider;

import org.springframework.beans.factory.InitializingBean;


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
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AuthByAdapterProvider implements InitializingBean,
    AuthenticationProvider {
    //~ Instance fields ========================================================

    private String key;

    //~ Methods ================================================================

    public void setKey(String key) {
        this.key = key;
    }

    public String getKey() {
        return key;
    }

    public void afterPropertiesSet() throws Exception {
        if (key == null) {
            throw new IllegalArgumentException(
                "A Key is required and should match that configured for the adapters");
        }
    }

    public Authentication authenticate(Authentication authentication)
        throws AuthenticationException {
        AuthByAdapter token = (AuthByAdapter) authentication;

        if (token.getKeyHash() == key.hashCode()) {
            return authentication;
        } else {
            throw new BadCredentialsException(
                "The presented AuthByAdapter implementation does not contain the expected key");
        }
    }

    public boolean supports(Class authentication) {
        if (AuthByAdapter.class.isAssignableFrom(authentication)) {
            return true;
        } else {
            return false;
        }
    }
}
