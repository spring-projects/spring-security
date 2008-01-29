/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.providers.x509;

import org.springframework.security.SpringSecurityMessageSource;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.BadCredentialsException;

import org.springframework.security.providers.AuthenticationProvider;
import org.springframework.security.providers.x509.cache.NullX509UserCache;

import org.springframework.security.userdetails.UserDetails;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;

import org.springframework.util.Assert;

import java.security.cert.X509Certificate;


/**
 * Processes an X.509 authentication request.<p>The request will typically originate from {@link
 * org.springframework.security.ui.x509.X509ProcessingFilter}).</p>
 *
 * @author Luke Taylor
 * @deprecated superceded by the preauth provider. Use the X.509 authentication support in org.springframework.security.ui.preauth.x509 instead
 *             or namespace support via the &lt;x509 /&gt; element. 
 * @version $Id$
 */
public class X509AuthenticationProvider implements AuthenticationProvider, InitializingBean, MessageSourceAware {
    //~ Static fields/initializers =====================================================================================

    private static final Log logger = LogFactory.getLog(X509AuthenticationProvider.class);

    //~ Instance fields ================================================================================================

    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
    private X509AuthoritiesPopulator x509AuthoritiesPopulator;
    private X509UserCache userCache = new NullX509UserCache();

    //~ Methods ========================================================================================================

	public void afterPropertiesSet() throws Exception {
        Assert.notNull(userCache, "An x509UserCache must be set");
        Assert.notNull(x509AuthoritiesPopulator, "An X509AuthoritiesPopulator must be set");
        Assert.notNull(this.messages, "A message source must be set");
    }

    /**
     * If the supplied authentication token contains a certificate then this will be passed to the configured
     * {@link X509AuthoritiesPopulator} to obtain the user details and authorities for the user identified by the
     * certificate.<p>If no certificate is present (for example, if the filter is applied to an HttpRequest for
     * which client authentication hasn't been configured in the container) then a BadCredentialsException will be
     * raised.</p>
     *
     * @param authentication the authentication request.
     *
     * @return an X509AuthenticationToken containing the authorities of the principal represented by the certificate.
     *
     * @throws AuthenticationException if the {@link X509AuthoritiesPopulator} rejects the certficate.
     * @throws BadCredentialsException if no certificate was presented in the authentication request.
     */
    public Authentication authenticate(Authentication authentication)
        throws AuthenticationException {
        if (!supports(authentication.getClass())) {
            return null;
        }

        if (logger.isDebugEnabled()) {
            logger.debug("X509 authentication request: " + authentication);
        }

        X509Certificate clientCertificate = (X509Certificate) authentication.getCredentials();

        if (clientCertificate == null) {
            throw new BadCredentialsException(messages.getMessage("X509AuthenticationProvider.certificateNull",
                    "Certificate is null"));
        }

        UserDetails user = userCache.getUserFromCache(clientCertificate);

        if (user == null) {
            logger.debug("Authenticating with certificate " + clientCertificate);
            user = x509AuthoritiesPopulator.getUserDetails(clientCertificate);
            userCache.putUserInCache(clientCertificate, user);
        }

        X509AuthenticationToken result = new X509AuthenticationToken(user, clientCertificate, user.getAuthorities());

        result.setDetails(authentication.getDetails());

        return result;
    }

    public void setMessageSource(MessageSource messageSource) {
        this.messages = new MessageSourceAccessor(messageSource);
    }

    public void setX509AuthoritiesPopulator(X509AuthoritiesPopulator x509AuthoritiesPopulator) {
        this.x509AuthoritiesPopulator = x509AuthoritiesPopulator;
    }

    public void setX509UserCache(X509UserCache cache) {
        this.userCache = cache;
    }

    public boolean supports(Class authentication) {
        return X509AuthenticationToken.class.isAssignableFrom(authentication);
    }
}
