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

package org.acegisecurity.providers.x509.populator;

import org.acegisecurity.AuthenticationException;
import org.acegisecurity.UserDetails;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.providers.dao.AuthenticationDao;
import org.acegisecurity.providers.x509.X509AuthoritiesPopulator;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oro.text.regex.*;

import java.security.cert.X509Certificate;



/**
 * Populates the X509 authorities via an {@link org.acegisecurity.providers.dao.AuthenticationDao}.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class DaoX509AuthoritiesPopulator implements X509AuthoritiesPopulator,
    InitializingBean {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(DaoX509AuthoritiesPopulator.class);

    //~ Instance fields ========================================================

    private AuthenticationDao authenticationDao;
    private String subjectDNRegex = "CN=(.*?),";
    private Pattern subjectDNPattern;

    //~ Methods ================================================================

    public void setAuthenticationDao(AuthenticationDao authenticationDao) {
        this.authenticationDao = authenticationDao;
    }

    /**
     * Sets the regular expression which will by used to extract the user name
     * from the certificate's Subject DN.
     * <p>
     * It should contain a single group; for example the default expression
     * "CN=(.*?)," matches the common name field. So "CN=Jimi Hendrix, OU=..."
     * will give a user name of "Jimi Hendrix".
     * </p>
     * <p>
     * The matches are case insensitive. So "emailAddress=(.*?)," will match
     * "EMAILADDRESS=jimi@hendrix.org, CN=..." giving a user name "jimi@hendrix.org"
     * </p>
     *
     * @param subjectDNRegex the regular expression to find in the subject
     */
    public void setSubjectDNRegex(String subjectDNRegex) {
        this.subjectDNRegex = subjectDNRegex;
    }

    public UserDetails getUserDetails(X509Certificate clientCert)
        throws AuthenticationException {

        String subjectDN = clientCert.getSubjectDN().getName();
        PatternMatcher matcher = new Perl5Matcher();

        if(!matcher.contains(subjectDN , subjectDNPattern)) {
            throw new BadCredentialsException("No matching pattern was found in subjectDN: " + subjectDN);
        }

        MatchResult match = matcher.getMatch();
        if(match.groups() != 2) { // 2 = 1 + the entire match
            throw new IllegalArgumentException("Regular expression must contain a single group ");
        }
        String userName = match.group(1);

        return this.authenticationDao.loadUserByUsername(userName);
    }

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(authenticationDao, "An authenticationDao must be set");

        Perl5Compiler compiler = new Perl5Compiler();

        try {
            subjectDNPattern = compiler.compile(subjectDNRegex,
                    Perl5Compiler.READ_ONLY_MASK | Perl5Compiler.CASE_INSENSITIVE_MASK);
        } catch (MalformedPatternException mpe) {
            throw new IllegalArgumentException("Malformed regular expression: " + subjectDNRegex);
        }
    }
}
