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

package net.sf.acegisecurity.providers.x509;

import net.sf.acegisecurity.providers.AuthenticationProvider;
import net.sf.acegisecurity.providers.x509.cache.NullX509UserCache;
import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationException;
import net.sf.acegisecurity.UserDetails;
import net.sf.acegisecurity.BadCredentialsException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.security.cert.X509Certificate;

/**
 * Processes an X.509 authentication request.
 * <p>
 * The request will typically originate from
 * {@link net.sf.acegisecurity.ui.x509.X509ProcessingFilter}).
 * </p>
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class X509AuthenticationProvider implements AuthenticationProvider,
    InitializingBean {
    //~ Static fields/initializers =============================================
    
    private static final Log logger = LogFactory.getLog(X509AuthenticationProvider.class);

    //~ Instance fields ========================================================

    private X509AuthoritiesPopulator x509AuthoritiesPopulator;
    private X509UserCache userCache = new NullX509UserCache();

    //~ Methods ================================================================

    public void setX509AuthoritiesPopulator(X509AuthoritiesPopulator x509AuthoritiesPopulator) {
        this.x509AuthoritiesPopulator = x509AuthoritiesPopulator;
    }

    public void setX509UserCache(X509UserCache cache) {
        this.userCache = cache;
    }

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(userCache, "An x509UserCache must be set");
        Assert.notNull(x509AuthoritiesPopulator, "An X509AuthoritiesPopulator must be set");
    }

    /**
     * If the supplied authentication token contains a certificate then this will be passed
     * to the configured {@link X509AuthoritiesPopulator}
     * to obtain the user details and authorities for the user identified by the certificate.
     * <p>
     * If no certificate is present (for example, if the filter is applied to an HttpRequest for which
     * client authentication hasn't been configured in the container) then a BadCredentialsException will be raised.
     * </p>
     *
     * @param authentication the authentication request.
     * @return an X509AuthenticationToken containing the authorities of the principal represented by the
     * certificate.
     * @throws AuthenticationException if the {@link X509AuthoritiesPopulator} rejects the certficate.
     * @throws BadCredentialsException if no certificate was presented in the authentication request.
     */
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!supports(authentication.getClass())) {
            return null;
        }

        if (logger.isDebugEnabled()) {
            logger.debug("X509 authentication request: " + authentication);
        }

        X509Certificate clientCertificate = (X509Certificate)authentication.getCredentials();

        if(clientCertificate == null) {
            throw new BadCredentialsException("Certificate is null.");
        }

        UserDetails user = userCache.getUserFromCache(clientCertificate);

        if(user == null) {
            logger.debug("Authenticating with certificate " + clientCertificate);
            user = x509AuthoritiesPopulator.getUserDetails(clientCertificate);
            userCache.putUserInCache(clientCertificate, user);
        }

        return new X509AuthenticationToken(user, clientCertificate, user.getAuthorities());
    }

    public boolean supports(Class authentication) {
        return X509AuthenticationToken.class.isAssignableFrom(authentication);
    }

}
