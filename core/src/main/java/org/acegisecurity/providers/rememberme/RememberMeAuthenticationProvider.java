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

package net.sf.acegisecurity.providers.rememberme;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationException;
import net.sf.acegisecurity.BadCredentialsException;
import net.sf.acegisecurity.providers.AuthenticationProvider;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.util.Assert;


/**
 * An {@link AuthenticationProvider} implementation that validates {@link
 * net.sf.acegisecurity.providers.rememberme.RememberMeAuthenticationToken}s.
 * 
 * <p>
 * To be successfully validated, the  {@link{@link
 * net.sf.acegisecurity.providers.rememberme.RememberMeAuthenticationToken#getKeyHash()}
 * must match this class' {@link #getKey()}.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class RememberMeAuthenticationProvider implements AuthenticationProvider,
    InitializingBean {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(RememberMeAuthenticationProvider.class);

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
        Assert.hasLength(key);
    }

    public Authentication authenticate(Authentication authentication)
        throws AuthenticationException {
        if (!supports(authentication.getClass())) {
            return null;
        }

        if (this.key.hashCode() != ((RememberMeAuthenticationToken) authentication)
            .getKeyHash()) {
            throw new BadCredentialsException(
                "The presented RememberMeAuthenticationToken does not contain the expected key");
        }

        return authentication;
    }

    public boolean supports(Class authentication) {
        return (RememberMeAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
