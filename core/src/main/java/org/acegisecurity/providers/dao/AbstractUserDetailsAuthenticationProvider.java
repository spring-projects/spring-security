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

package org.acegisecurity.providers.dao;

import org.acegisecurity.AccountExpiredException;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.CredentialsExpiredException;
import org.acegisecurity.DisabledException;
import org.acegisecurity.LockedException;
import org.acegisecurity.UserDetails;
import org.acegisecurity.providers.AuthenticationProvider;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.dao.cache.NullUserCache;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.util.Assert;


/**
 * A base {@link AuthenticationProvider} that allows subclasses to override and
 * work with {@link org.acegisecurity.UserDetails} objects. The class is
 * designed to respond to {@link UsernamePasswordAuthenticationToken}
 * authentication requests.
 * 
 * <p>
 * Upon successful validation, a
 * <code>UsernamePasswordAuthenticationToken</code> will be created and
 * returned to the caller. The token will include as its principal either a
 * <code>String</code> representation of the username, or the {@link
 * UserDetails} that was returned from the authentication repository. Using
 * <code>String</code> is appropriate if a container adapter is being used, as
 * it expects <code>String</code> representations of the username. Using
 * <code>UserDetails</code> is appropriate if you require access to additional
 * properties of the authenticated user, such as email addresses,
 * human-friendly names etc. As container adapters are not recommended to be
 * used, and <code>UserDetails</code> implementations provide additional
 * flexibility, by default a <code>UserDetails</code> is returned. To override
 * this default, set the {@link #setForcePrincipalAsString} to
 * <code>true</code>.
 * </p>
 * 
 * <P>
 * Caching is handled via the <code>UserDetails</code> object being placed in
 * the {@link UserCache}. This ensures that subsequent requests with the same
 * username can be validated without needing to query the {@link
 * AuthenticationDao}. It should be noted that if a user appears to present an
 * incorrect password, the {@link AuthenticationDao} will be queried to
 * confirm the most up-to-date password was used for comparison.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public abstract class AbstractUserDetailsAuthenticationProvider
    implements AuthenticationProvider, InitializingBean {
    //~ Instance fields ========================================================

    private UserCache userCache = new NullUserCache();
    private boolean forcePrincipalAsString = false;

    //~ Methods ================================================================

    public void setForcePrincipalAsString(boolean forcePrincipalAsString) {
        this.forcePrincipalAsString = forcePrincipalAsString;
    }

    public boolean isForcePrincipalAsString() {
        return forcePrincipalAsString;
    }

    public void setUserCache(UserCache userCache) {
        this.userCache = userCache;
    }

    public UserCache getUserCache() {
        return userCache;
    }

    public final void afterPropertiesSet() throws Exception {
        Assert.notNull(this.userCache, "A user cache must be set");
        doAfterPropertiesSet();
    }

    public Authentication authenticate(Authentication authentication)
        throws AuthenticationException {
        Assert.isInstanceOf(UsernamePasswordAuthenticationToken.class,
            authentication,
            "Only UsernamePasswordAuthenticationToken is supported");

        // Determine username
        String username = (authentication.getPrincipal() == null)
            ? "NONE_PROVIDED" : authentication.getName();

        boolean cacheWasUsed = true;
        UserDetails user = this.userCache.getUserFromCache(username);

        if (user == null) {
            cacheWasUsed = false;
            user = retrieveUser(username,
                    (UsernamePasswordAuthenticationToken) authentication);
            Assert.notNull(user,
                "retrieveUser returned null - a violation of the interface contract");
        }

        if (!user.isAccountNonLocked()) {
            throw new LockedException("User account is locked");
        }

        if (!user.isEnabled()) {
            throw new DisabledException("User is disabled");
        }

        if (!user.isAccountNonExpired()) {
            throw new AccountExpiredException("User account has expired");
        }

        // This check must come here, as we don't want to tell users
        // about account status unless they presented the correct credentials
        try {
            additionalAuthenticationChecks(user,
                (UsernamePasswordAuthenticationToken) authentication);
        } catch (AuthenticationException exception) {
            // There was a problem, so try again after checking we're using latest data
            cacheWasUsed = false;
            user = retrieveUser(username,
                    (UsernamePasswordAuthenticationToken) authentication);
            additionalAuthenticationChecks(user,
                (UsernamePasswordAuthenticationToken) authentication);
        }

        if (!user.isCredentialsNonExpired()) {
            throw new CredentialsExpiredException(
                "User credentials have expired");
        }

        if (!cacheWasUsed) {
            this.userCache.putUserInCache(user);
        }

        Object principalToReturn = user;

        if (forcePrincipalAsString) {
            principalToReturn = user.getUsername();
        }

        return createSuccessAuthentication(principalToReturn, authentication,
            user);
    }

    public boolean supports(Class authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }

    /**
     * Allows subclasses to perform any additional checks of a returned (or
     * cached) <code>UserDetails</code> for a given authentication request.
     * Generally a subclass will at least compare the {@link
     * Authentication#getCredentials()} with a {@link
     * UserDetails#getPassword()}. If custom logic is needed to compare
     * additional properties of <code>UserDetails</code> and/or
     * <code>UsernamePasswordAuthenticationToken</code>, these should also
     * appear in this method.
     *
     * @param userDetails as retrieved from the {@link #retrieveUser(String,
     *        UsernamePasswordAuthenticationToken)} or <code>UserCache</code>
     * @param authentication the current request that needs to be authenticated
     *
     * @throws AuthenticationException AuthenticationException if the
     *         credentials could not be validated (generally a
     *         <code>BadCredentialsException</code>, an
     *         <code>AuthenticationServiceException</code>)
     */
    protected abstract void additionalAuthenticationChecks(
        UserDetails userDetails,
        UsernamePasswordAuthenticationToken authentication)
        throws AuthenticationException;

    protected void doAfterPropertiesSet() throws Exception {}

    /**
     * Allows subclasses to actually retrieve the <code>UserDetails</code> from
     * an implementation-specific location, with the option of throwing an
     * <code>AuthenticationException</code> immediately if the presented
     * credentials are incorrect (this is especially useful if it is necessary
     * to bind to a resource as the user in order to obtain or generate a
     * <code>UserDetails</code>).
     * 
     * <p>
     * Subclasses are not required to perform any caching, as the
     * <code>AbstractUserDetailsAuthenticationProvider</code> will by default
     * cache the <code>UserDetails</code>. The caching of
     * <code>UserDetails</code> does present additional complexity as this
     * means subsequent requests that rely on the cache will need to still
     * have their credentials validated, even if the correctness of
     * credentials was assured by subclasses adopting a binding-based strategy
     * in this method. Accordingly it is important that subclasses either
     * disable caching (if they want to ensure that this method is the only
     * method that is capable of authenticating a request, as no
     * <code>UserDetails</code> will ever be cached) or ensure subclasses
     * implement {@link #additionalAuthenticationChecks(UserDetails,
     * UsernamePasswordAuthenticationToken)} to compare the credentials of a
     * cached <code>UserDetails</code> with subsequent authentication
     * requests.
     * </p>
     * 
     * <p>
     * Most of the time subclasses will not perform credentials inspection in
     * this method, instead performing it in {@link
     * #additionalAuthenticationChecks(UserDetails,
     * UsernamePasswordAuthenticationToken)} so that code related to
     * credentials validation need not be duplicated across two methods.
     * </p>
     *
     * @param username The username to retrieve
     * @param authentication The authentication request, which subclasses
     *        <em>may</em> need to perform a binding-based retrieval of the
     *        <code>UserDetails</code>
     *
     * @return the user information (never <code>null</code> - instead an
     *         exception should the thrown)
     *
     * @throws AuthenticationException if the credentials could not be
     *         validated (generally a <code>BadCredentialsException</code>, an
     *         <code>AuthenticationServiceException</code> or
     *         <code>UserNotFoundException</code>)
     */
    protected abstract UserDetails retrieveUser(String username,
        UsernamePasswordAuthenticationToken authentication)
        throws AuthenticationException;

    /**
     * Creates a successful {@link Authentication} object.
     * 
     * <P>
     * Protected so subclasses can override.
     * </p>
     * 
     * <P>
     * Subclasses will usually store the original credentials the user supplied
     * (not salted or encoded passwords) in the returned
     * <code>Authentication</code> object.
     * </p>
     *
     * @param principal that should be the principal in the returned object
     *        (defined by the {@link #isForcePrincipalAsString()} method)
     * @param authentication that was presented to the
     *        <code>DaoAuthenticationProvider</code> for validation
     * @param user that was loaded by the <code>AuthenticationDao</code>
     *
     * @return the successful authentication token
     */
    protected Authentication createSuccessAuthentication(Object principal,
        Authentication authentication, UserDetails user) {
        // Ensure we return the original credentials the user supplied,
        // so subsequent attempts are successful even with encoded passwords.
        // Also ensure we return the original getDetails(), so that future
        // authentication events after cache expiry contain the details
        UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(principal,
                authentication.getCredentials(), user.getAuthorities());
        result.setDetails((authentication.getDetails() != null)
            ? authentication.getDetails() : null);

        return result;
    }
}
