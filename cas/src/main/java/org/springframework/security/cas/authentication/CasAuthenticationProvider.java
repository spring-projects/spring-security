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

package org.springframework.security.cas.authentication;

import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.TicketValidationException;
import org.jasig.cas.client.validation.TicketValidator;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.userdetails.*;
import org.springframework.util.Assert;


/**
 * An {@link AuthenticationProvider} implementation that integrates with JA-SIG Central Authentication Service
 * (CAS).
 * <p>
 * This <code>AuthenticationProvider</code> is capable of validating  {@link UsernamePasswordAuthenticationToken}
 * requests which contain a <code>principal</code> name equal to either
 * {@link CasAuthenticationFilter#CAS_STATEFUL_IDENTIFIER} or {@link CasAuthenticationFilter#CAS_STATELESS_IDENTIFIER}.
 * It can also validate a previously created {@link CasAuthenticationToken}.
 *
 * @author Ben Alex
 * @author Scott Battaglia
 * @version $Id$
 */
public class CasAuthenticationProvider implements AuthenticationProvider, InitializingBean, MessageSourceAware {

    //~ Instance fields ================================================================================================

    private AuthenticationUserDetailsService authenticationUserDetailsService;

    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
    private StatelessTicketCache statelessTicketCache = new NullStatelessTicketCache();
    private String key;
    private TicketValidator ticketValidator;
    private ServiceProperties serviceProperties;

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(this.authenticationUserDetailsService, "An authenticationUserDetailsService must be set");
        Assert.notNull(this.ticketValidator, "A ticketValidator must be set");
        Assert.notNull(this.statelessTicketCache, "A statelessTicketCache must be set");
        Assert.hasText(this.key, "A Key is required so CasAuthenticationProvider can identify tokens it previously authenticated");
        Assert.notNull(this.messages, "A message source must be set");
        Assert.notNull(this.serviceProperties, "serviceProperties is a required field.");
    }

    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!supports(authentication.getClass())) {
            return null;
        }

        if (authentication instanceof UsernamePasswordAuthenticationToken
            && (!CasAuthenticationFilter.CAS_STATEFUL_IDENTIFIER.equals(authentication.getPrincipal().toString())
            && !CasAuthenticationFilter.CAS_STATELESS_IDENTIFIER.equals(authentication.getPrincipal().toString()))) {
            // UsernamePasswordAuthenticationToken not CAS related
            return null;
        }

        // If an existing CasAuthenticationToken, just check we created it
        if (authentication instanceof CasAuthenticationToken) {
            if (this.key.hashCode() == ((CasAuthenticationToken) authentication).getKeyHash()) {
                return authentication;
            } else {
                throw new BadCredentialsException(messages.getMessage("CasAuthenticationProvider.incorrectKey",
                        "The presented CasAuthenticationToken does not contain the expected key"));
            }
        }

        // Ensure credentials are presented
        if ((authentication.getCredentials() == null) || "".equals(authentication.getCredentials())) {
            throw new BadCredentialsException(messages.getMessage("CasAuthenticationProvider.noServiceTicket",
                    "Failed to provide a CAS service ticket to validate"));
        }

        boolean stateless = false;

        if (authentication instanceof UsernamePasswordAuthenticationToken
            && CasAuthenticationFilter.CAS_STATELESS_IDENTIFIER.equals(authentication.getPrincipal())) {
            stateless = true;
        }

        CasAuthenticationToken result = null;

        if (stateless) {
            // Try to obtain from cache
            result = statelessTicketCache.getByTicketId(authentication.getCredentials().toString());
        }

        if (result == null) {
            result = this.authenticateNow(authentication);
            result.setDetails(authentication.getDetails());
        }

        if (stateless) {
            // Add to cache
            statelessTicketCache.putTicketInCache(result);
        }

        return result;
    }

    private CasAuthenticationToken authenticateNow(final Authentication authentication) throws AuthenticationException {
        try {
            final Assertion assertion = this.ticketValidator.validate(authentication.getCredentials().toString(), serviceProperties.getService());
            final UserDetails userDetails = loadUserByAssertion(assertion);
            userDetailsChecker.check(userDetails);
            return new CasAuthenticationToken(this.key, userDetails, authentication.getCredentials(), userDetails.getAuthorities(), userDetails, assertion);
        } catch (final TicketValidationException e) {
            throw new BadCredentialsException(e.getMessage(), e);
        }
    }

    /**
     * Template method for retrieving the UserDetails based on the assertion.  Default is to call configured userDetailsService and pass the username.  Deployers
     * can override this method and retrieve the user based on any criteria they desire.
     *
     * @param assertion The CAS Assertion.
     * @return the UserDetails.
     */
    protected UserDetails loadUserByAssertion(final Assertion assertion) {
        final CasAssertionAuthenticationToken token = new CasAssertionAuthenticationToken(assertion, "");
        return this.authenticationUserDetailsService.loadUserDetails(token);
    }

    @Deprecated
    /**
     * @deprecated as of 3.0.  Use the {@link org.springframework.security.cas.authentication.CasAuthenticationProvider#setAuthenticationUserDetailsService(org.springframework.security.core.userdetails.AuthenticationUserDetailsService)} instead.
     */
    public void setUserDetailsService(final UserDetailsService userDetailsService) {
        this.authenticationUserDetailsService = new UserDetailsByNameServiceWrapper(userDetailsService);
    }

    public void setAuthenticationUserDetailsService(final AuthenticationUserDetailsService authenticationUserDetailsService) {
        this.authenticationUserDetailsService = authenticationUserDetailsService;
    }

    public void setServiceProperties(final ServiceProperties serviceProperties) {
        this.serviceProperties = serviceProperties;
    }

    protected String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public StatelessTicketCache getStatelessTicketCache() {
        return statelessTicketCache;
    }

    protected TicketValidator getTicketValidator() {
        return ticketValidator;
    }

    public void setMessageSource(final MessageSource messageSource) {
        this.messages = new MessageSourceAccessor(messageSource);
    }

    public void setStatelessTicketCache(final StatelessTicketCache statelessTicketCache) {
        this.statelessTicketCache = statelessTicketCache;
    }

    public void setTicketValidator(final TicketValidator ticketValidator) {
        this.ticketValidator = ticketValidator;
    }

    public boolean supports(final Class<? extends Object> authentication) {
        if (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication)) {
            return true;
        } else if (CasAuthenticationToken.class.isAssignableFrom(authentication)) {
            return true;
        } else {
            return false;
        }
    }
}
