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

package net.sf.acegisecurity.providers.dao;

import net.sf.acegisecurity.AccountExpiredException;
import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationException;
import net.sf.acegisecurity.AuthenticationServiceException;
import net.sf.acegisecurity.BadCredentialsException;
import net.sf.acegisecurity.CredentialsExpiredException;
import net.sf.acegisecurity.DisabledException;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.LockedException;
import net.sf.acegisecurity.UserDetails;
import net.sf.acegisecurity.providers.AuthenticationProvider;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import net.sf.acegisecurity.providers.dao.cache.NullUserCache;
import net.sf.acegisecurity.providers.dao.event.AuthenticationFailureAccountExpiredEvent;
import net.sf.acegisecurity.providers.dao.event.AuthenticationFailureAccountLockedEvent;
import net.sf.acegisecurity.providers.dao.event.AuthenticationFailureCredentialsExpiredEvent;
import net.sf.acegisecurity.providers.dao.event.AuthenticationFailureDisabledEvent;
import net.sf.acegisecurity.providers.dao.event.AuthenticationFailureUsernameOrPasswordEvent;
import net.sf.acegisecurity.providers.dao.event.AuthenticationSuccessEvent;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.InitializingBean;

import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

import org.springframework.dao.DataAccessException;


/**
 * An {@link AuthenticationProvider} implementation that retrieves user details
 * from a {@link PasswordAuthenticationDao}.
 * 
 * <p>
 * This <code>AuthenticationProvider</code> is capable of validating {@link
 * UsernamePasswordAuthenticationToken} requests containing the correct
 * username, password and when the user is not disabled.
 * </p>
 * 
 * <p>
 * Unlike {@link DaoAuthenticationProvider}, the responsibility for password
 * validation is delegated to <code>PasswordAuthenticationDao</code>.
 * </p>
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
 * <p>
 * Caching is handled via the <code>UserDetails</code> object being placed in
 * the {@link UserCache}. This ensures that subsequent requests with the same
 * username and password can be validated without needing to query the {@link
 * PasswordAuthenticationDao}. It should be noted that if a user appears to
 * present an incorrect password, the {@link PasswordAuthenticationDao} will
 * be queried to confirm the most up-to-date password was used for comparison.
 * </p>
 * 
 * <p>
 * If an application context is detected (which is automatically the case when
 * the bean is started within a Spring container), application events will be
 * published to the context. See {@link
 * net.sf.acegisecurity.providers.dao.event.AuthenticationEvent} for further
 * information.
 * </p>
 *
 * @author Karel Miarka
 */
public class PasswordDaoAuthenticationProvider implements AuthenticationProvider,
    InitializingBean, ApplicationContextAware {
    //~ Instance fields ========================================================

    private ApplicationContext context;
    private PasswordAuthenticationDao authenticationDao;
    private UserCache userCache = new NullUserCache();
    private boolean forcePrincipalAsString = false;

    //~ Methods ================================================================

    public void setApplicationContext(ApplicationContext applicationContext)
        throws BeansException {
        this.context = applicationContext;
    }

    public ApplicationContext getContext() {
        return context;
    }

    public void setForcePrincipalAsString(boolean forcePrincipalAsString) {
        this.forcePrincipalAsString = forcePrincipalAsString;
    }

    public boolean isForcePrincipalAsString() {
        return forcePrincipalAsString;
    }

    public void setPasswordAuthenticationDao(
        PasswordAuthenticationDao authenticationDao) {
        this.authenticationDao = authenticationDao;
    }

    public PasswordAuthenticationDao getPasswordAuthenticationDao() {
        return authenticationDao;
    }

    public void setUserCache(UserCache userCache) {
        this.userCache = userCache;
    }

    public UserCache getUserCache() {
        return userCache;
    }

    public void afterPropertiesSet() throws Exception {
        if (this.authenticationDao == null) {
            throw new IllegalArgumentException(
                "A Password authentication DAO must be set");
        }

        if (this.userCache == null) {
            throw new IllegalArgumentException("A user cache must be set");
        }
    }

    public Authentication authenticate(Authentication authentication)
        throws AuthenticationException {
        // Determine username
        String username = authentication.getPrincipal().toString();

        if (authentication.getPrincipal() instanceof UserDetails) {
            username = ((UserDetails) authentication.getPrincipal())
                .getUsername();
        }

        String password = authentication.getCredentials().toString();

        boolean cacheWasUsed = true;
        UserDetails user = this.userCache.getUserFromCache(username);

        // Check if the provided password is the same as the password in cache
        if ((user != null) && !password.equals(user.getPassword())) {
            user = null;
            this.userCache.removeUserFromCache(username);
        }

        if (user == null) {
            cacheWasUsed = false;

            try {
                user = getUserFromBackend(username, password);
            } catch (BadCredentialsException ex) {
                if (this.context != null) {
                    if ((username == null) || "".equals(username)) {
                        username = "NONE_PROVIDED";
                    }

                    context.publishEvent(new AuthenticationFailureUsernameOrPasswordEvent(
                            authentication,
                            new User(username, "*****", false, false, false,
                                false, new GrantedAuthority[0])));
                }

                throw ex;
            }
        }

        if (!user.isEnabled()) {
            if (this.context != null) {
                context.publishEvent(new AuthenticationFailureDisabledEvent(
                        authentication, user));
            }

            throw new DisabledException("User is disabled");
        }

        if (!user.isAccountNonExpired()) {
            if (this.context != null) {
                context.publishEvent(new AuthenticationFailureAccountExpiredEvent(
                        authentication, user));
            }

            throw new AccountExpiredException("User account has expired");
        }

        if (!user.isAccountNonLocked()) {
            if (this.context != null) {
                context.publishEvent(new AuthenticationFailureAccountLockedEvent(
                        authentication, user));
            }

            throw new LockedException("User account is locked");
        }

        if (!user.isCredentialsNonExpired()) {
            if (this.context != null) {
                context.publishEvent(new AuthenticationFailureCredentialsExpiredEvent(
                        authentication, user));
            }

            throw new CredentialsExpiredException(
                "User credentials have expired");
        }

        if (!cacheWasUsed) {
            // Put into cache
            this.userCache.putUserInCache(user);

            // As this appears to be an initial login, publish the event
            if (this.context != null) {
                context.publishEvent(new AuthenticationSuccessEvent(
                        authentication, user));
            }
        }

        Object principalToReturn = user;

        if (forcePrincipalAsString) {
            principalToReturn = user.getUsername();
        }

        return createSuccessAuthentication(principalToReturn, authentication,
            user);
    }

    public boolean supports(Class authentication) {
        if (UsernamePasswordAuthenticationToken.class.isAssignableFrom(
                authentication)) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Creates a successful {@link Authentication} object.
     * 
     * <P>
     * Protected so subclasses can override. This might be required if multiple
     * credentials need to be placed into a custom <code>Authentication</code>
     * object, such as a password as well as a ZIP code.
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
     *        <code>PasswordDaoAuthenticationProvider</code> for validation
     * @param user that was loaded by the
     *        <code>PasswordAuthenticationDao</code>
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
            ? authentication.getDetails().toString() : null);

        return result;
    }

    private UserDetails getUserFromBackend(String username, String password) {
        try {
            return this.authenticationDao.loadUserByUsernameAndPassword(username,
                password);
        } catch (DataAccessException repositoryProblem) {
            throw new AuthenticationServiceException(repositoryProblem
                .getMessage(), repositoryProblem);
        }
    }
}
