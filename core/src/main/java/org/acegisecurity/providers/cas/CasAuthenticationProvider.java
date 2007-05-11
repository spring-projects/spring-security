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

package org.acegisecurity.providers.cas;

import org.acegisecurity.AcegiMessageSource;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.BadCredentialsException;

import org.acegisecurity.providers.AuthenticationProvider;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;

import org.acegisecurity.ui.cas.CasProcessingFilter;

import org.acegisecurity.userdetails.UserDetails;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.core.Ordered;

import org.springframework.util.Assert;


/**
 * An {@link AuthenticationProvider} implementation that integrates with JA-SIG Central Authentication Service
 * (CAS).<p>This <code>AuthenticationProvider</code> is capable of validating  {@link
 * UsernamePasswordAuthenticationToken} requests which contain a <code>principal</code> name equal to either {@link
 * CasProcessingFilter#CAS_STATEFUL_IDENTIFIER} or {@link CasProcessingFilter#CAS_STATELESS_IDENTIFIER}. It can also
 * validate a previously created {@link CasAuthenticationToken}.</p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class CasAuthenticationProvider implements AuthenticationProvider, InitializingBean, MessageSourceAware, Ordered {
    //~ Static fields/initializers =====================================================================================

    private static final Log logger = LogFactory.getLog(CasAuthenticationProvider.class);

    //~ Instance fields ================================================================================================

    private CasAuthoritiesPopulator casAuthoritiesPopulator;
    private CasProxyDecider casProxyDecider;
    protected MessageSourceAccessor messages = AcegiMessageSource.getAccessor();
    private StatelessTicketCache statelessTicketCache;
    private String key;
    private TicketValidator ticketValidator;
    private int order = -1; // default: same as non-Ordered

    //~ Methods ========================================================================================================

    public int getOrder() {
		return order;
	}

	public void setOrder(int order) {
		this.order = order;
	}

	public void afterPropertiesSet() throws Exception {
        Assert.notNull(this.casAuthoritiesPopulator, "A casAuthoritiesPopulator must be set");
        Assert.notNull(this.ticketValidator, "A ticketValidator must be set");
        Assert.notNull(this.casProxyDecider, "A casProxyDecider must be set");
        Assert.notNull(this.statelessTicketCache, "A statelessTicketCache must be set");
        Assert.notNull(key,
            "A Key is required so CasAuthenticationProvider can identify tokens it previously authenticated");
        Assert.notNull(this.messages, "A message source must be set");
    }

    public Authentication authenticate(Authentication authentication)
        throws AuthenticationException {
        if (!supports(authentication.getClass())) {
            return null;
        }

        if (authentication instanceof UsernamePasswordAuthenticationToken
            && (!CasProcessingFilter.CAS_STATEFUL_IDENTIFIER.equals(authentication.getPrincipal().toString())
            && !CasProcessingFilter.CAS_STATELESS_IDENTIFIER.equals(authentication.getPrincipal().toString()))) {
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
            && CasProcessingFilter.CAS_STATELESS_IDENTIFIER.equals(authentication.getPrincipal())) {
            stateless = true;
        }

        CasAuthenticationToken result = null;

        if (stateless) {
            // Try to obtain from cache
            result = statelessTicketCache.getByTicketId(authentication.getCredentials().toString());
        }

        if (result == null) {
            result = this.authenticateNow(authentication);
        }

        if (stateless) {
            // Add to cache
            statelessTicketCache.putTicketInCache(result);
        }

        return result;
    }

    private CasAuthenticationToken authenticateNow(Authentication authentication)
        throws AuthenticationException {
        // Validate
        TicketResponse response = ticketValidator.confirmTicketValid(authentication.getCredentials().toString());

        // Check proxy list is trusted
        this.casProxyDecider.confirmProxyListTrusted(response.getProxyList());

        // Lookup user details
        UserDetails userDetails = this.casAuthoritiesPopulator.getUserDetails(response.getUser());

        // Construct CasAuthenticationToken
        return new CasAuthenticationToken(this.key, userDetails, authentication.getCredentials(),
            userDetails.getAuthorities(), userDetails, response.getProxyList(), response.getProxyGrantingTicketIou());
    }

    public CasAuthoritiesPopulator getCasAuthoritiesPopulator() {
        return casAuthoritiesPopulator;
    }

    public CasProxyDecider getCasProxyDecider() {
        return casProxyDecider;
    }

    public String getKey() {
        return key;
    }

    public StatelessTicketCache getStatelessTicketCache() {
        return statelessTicketCache;
    }

    public TicketValidator getTicketValidator() {
        return ticketValidator;
    }

    public void setCasAuthoritiesPopulator(CasAuthoritiesPopulator casAuthoritiesPopulator) {
        this.casAuthoritiesPopulator = casAuthoritiesPopulator;
    }

    public void setCasProxyDecider(CasProxyDecider casProxyDecider) {
        this.casProxyDecider = casProxyDecider;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public void setMessageSource(MessageSource messageSource) {
        this.messages = new MessageSourceAccessor(messageSource);
    }

    public void setStatelessTicketCache(StatelessTicketCache statelessTicketCache) {
        this.statelessTicketCache = statelessTicketCache;
    }

    public void setTicketValidator(TicketValidator ticketValidator) {
        this.ticketValidator = ticketValidator;
    }

    public boolean supports(Class authentication) {
        if (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication)) {
            return true;
        } else if (CasAuthenticationToken.class.isAssignableFrom(authentication)) {
            return true;
        } else {
            return false;
        }
    }
}
