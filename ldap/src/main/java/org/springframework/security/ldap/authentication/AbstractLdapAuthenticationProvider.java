/*
 * Copyright 2002-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */package org.springframework.security.ldap.authentication;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.security.ldap.userdetails.UserDetailsContextMapper;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.*;

/**
 * Base class for the standard {@code LdapAuthenticationProvider} and the
 * {@code ActiveDirectoryLdapAuthenticationProvider}.
 *
 * @author Luke Taylor
 * @since 3.1
 */
public abstract class AbstractLdapAuthenticationProvider implements AuthenticationProvider, MessageSourceAware {
    protected final Log logger = LogFactory.getLog(getClass());
    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
    private boolean useAuthenticationRequestCredentials = true;
    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();
    protected UserDetailsContextMapper userDetailsContextMapper = new LdapUserDetailsMapper();

    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Assert.isInstanceOf(UsernamePasswordAuthenticationToken.class, authentication,
            messages.getMessage("LdapAuthenticationProvider.onlySupports",
                "Only UsernamePasswordAuthenticationToken is supported"));

        final UsernamePasswordAuthenticationToken userToken = (UsernamePasswordAuthenticationToken)authentication;

        String username = userToken.getName();
        String password = (String) authentication.getCredentials();

        if (logger.isDebugEnabled()) {
            logger.debug("Processing authentication request for user: " + username);
        }

        if (!StringUtils.hasLength(username)) {
            throw new BadCredentialsException(messages.getMessage("LdapAuthenticationProvider.emptyUsername",
                    "Empty Username"));
        }

        if (!StringUtils.hasLength(password)) {
            throw new BadCredentialsException(messages.getMessage("AbstractLdapAuthenticationProvider.emptyPassword",
                    "Empty Password"));
        }

        Assert.notNull(password, "Null password was supplied in authentication token");

        DirContextOperations userData = doAuthentication(userToken);

        UserDetails user = userDetailsContextMapper.mapUserFromContext(userData, authentication.getName(),
                    loadUserAuthorities(userData, authentication.getName(), (String)authentication.getCredentials()));

        return createSuccessfulAuthentication(userToken, user);
    }

    protected abstract DirContextOperations doAuthentication(UsernamePasswordAuthenticationToken auth);

    protected abstract Collection<? extends GrantedAuthority> loadUserAuthorities(DirContextOperations userData, String username, String password);

    /**
     * Creates the final {@code Authentication} object which will be returned from the {@code authenticate} method.
     *
     * @param authentication the original authentication request token
     * @param user the <tt>UserDetails</tt> instance returned by the configured <tt>UserDetailsContextMapper</tt>.
     * @return the Authentication object for the fully authenticated user.
     */
    protected Authentication createSuccessfulAuthentication(UsernamePasswordAuthenticationToken authentication,
            UserDetails user) {
        Object password = useAuthenticationRequestCredentials ? authentication.getCredentials() : user.getPassword();

        UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(user, password,
                authoritiesMapper.mapAuthorities(user.getAuthorities()));
        result.setDetails(authentication.getDetails());

        return result;
    }

    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

    /**
     * Determines whether the supplied password will be used as the credentials in the successful authentication
     * token. If set to false, then the password will be obtained from the UserDetails object
     * created by the configured {@code UserDetailsContextMapper}.
     * Often it will not be possible to read the password from the directory, so defaults to true.
     *
     * @param useAuthenticationRequestCredentials
     */
    public void setUseAuthenticationRequestCredentials(boolean useAuthenticationRequestCredentials) {
        this.useAuthenticationRequestCredentials = useAuthenticationRequestCredentials;
    }

    public void setMessageSource(MessageSource messageSource) {
        this.messages = new MessageSourceAccessor(messageSource);
    }

    public void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
        this.authoritiesMapper = authoritiesMapper;
    }

    /**
     * Allows a custom strategy to be used for creating the <tt>UserDetails</tt> which will be stored as the principal
     * in the <tt>Authentication</tt> returned by the
     * {@link #createSuccessfulAuthentication(org.springframework.security.authentication.UsernamePasswordAuthenticationToken, org.springframework.security.core.userdetails.UserDetails)} method.
     *
     * @param userDetailsContextMapper the strategy instance. If not set, defaults to a simple
     * <tt>LdapUserDetailsMapper</tt>.
     */
    public void setUserDetailsContextMapper(UserDetailsContextMapper userDetailsContextMapper) {
        Assert.notNull(userDetailsContextMapper, "UserDetailsContextMapper must not be null");
        this.userDetailsContextMapper = userDetailsContextMapper;
    }

    /**
     * Provides access to the injected {@code UserDetailsContextMapper} strategy for use by subclasses.
     */
    protected UserDetailsContextMapper getUserDetailsContextMapper() {
        return userDetailsContextMapper;
    }
}
