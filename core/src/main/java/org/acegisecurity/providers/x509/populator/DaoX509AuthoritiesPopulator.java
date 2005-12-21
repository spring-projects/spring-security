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

package org.acegisecurity.providers.x509.populator;

import java.security.cert.X509Certificate;

import org.acegisecurity.AcegiMessageSource;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.providers.x509.X509AuthoritiesPopulator;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oro.text.regex.MalformedPatternException;
import org.apache.oro.text.regex.MatchResult;
import org.apache.oro.text.regex.Pattern;
import org.apache.oro.text.regex.PatternMatcher;
import org.apache.oro.text.regex.Perl5Compiler;
import org.apache.oro.text.regex.Perl5Matcher;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.util.Assert;


/**
 * Populates the X509 authorities via an {@link
 * org.acegisecurity.userdetails.UserDetailsService}.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class DaoX509AuthoritiesPopulator implements X509AuthoritiesPopulator,
    InitializingBean, MessageSourceAware {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(DaoX509AuthoritiesPopulator.class);

    //~ Instance fields ========================================================

    private UserDetailsService userDetailsService;
    protected MessageSourceAccessor messages = AcegiMessageSource.getAccessor();
    private Pattern subjectDNPattern;
    private String subjectDNRegex = "CN=(.*?),";

    //~ Methods ================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(userDetailsService, "An authenticationDao must be set");
        Assert.notNull(this.messages, "A message source must be set");

        Perl5Compiler compiler = new Perl5Compiler();

        try {
            subjectDNPattern = compiler.compile(subjectDNRegex,
                    Perl5Compiler.READ_ONLY_MASK
                    | Perl5Compiler.CASE_INSENSITIVE_MASK);
        } catch (MalformedPatternException mpe) {
            throw new IllegalArgumentException("Malformed regular expression: "
                + subjectDNRegex);
        }
    }

    public UserDetails getUserDetails(X509Certificate clientCert)
        throws AuthenticationException {
        String subjectDN = clientCert.getSubjectDN().getName();
        PatternMatcher matcher = new Perl5Matcher();

        if (!matcher.contains(subjectDN, subjectDNPattern)) {
            throw new BadCredentialsException(messages.getMessage(
                    "DaoX509AuthoritiesPopulator.noMatching",
                    new Object[] {subjectDN},
                    "No matching pattern was found in subjectDN: {0}"));
        }

        MatchResult match = matcher.getMatch();

        if (match.groups() != 2) { // 2 = 1 + the entire match
            throw new IllegalArgumentException(
                "Regular expression must contain a single group ");
        }

        String userName = match.group(1);

        return this.userDetailsService.loadUserByUsername(userName);
    }

    public void setUserDetailsService(UserDetailsService authenticationDao) {
        this.userDetailsService = authenticationDao;
    }

    public void setMessageSource(MessageSource messageSource) {
        this.messages = new MessageSourceAccessor(messageSource);
    }

    /**
     * Sets the regular expression which will by used to extract the user name
     * from the certificate's Subject DN.
     *
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
}
