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

package net.sf.acegisecurity.providers.dao;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationException;
import net.sf.acegisecurity.AuthenticationServiceException;
import net.sf.acegisecurity.BadCredentialsException;
import net.sf.acegisecurity.DisabledException;
import net.sf.acegisecurity.providers.AuthenticationProvider;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import net.sf.acegisecurity.providers.dao.cache.NullUserCache;
import net.sf.acegisecurity.providers.dao.event.AuthenticationFailureDisabledEvent;
import net.sf.acegisecurity.providers.dao.event.AuthenticationFailurePasswordEvent;
import net.sf.acegisecurity.providers.dao.event.AuthenticationSuccessEvent;
import net.sf.acegisecurity.providers.encoding.PasswordEncoder;
import net.sf.acegisecurity.providers.encoding.PlaintextPasswordEncoder;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.InitializingBean;

import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

import org.springframework.dao.DataAccessException;


/**
 * An {@link AuthenticationProvider} implementation that retrieves user details
 * from an {@link AuthenticationDao}.
 * 
 * <p>
 * This <code>AuthenticationProvider</code> is capable of validating {@link
 * UsernamePasswordAuthenticationToken} requests contain the correct username,
 * password and the user is not disabled.
 * </p>
 * 
 * <p>
 * Upon successful validation, a
 * <code>UsernamePasswordAuthenticationToken</code> will be created and
 * returned to the caller. In addition, the {@link User} will be placed in the
 * {@link UserCache} so that subsequent requests with the same username can be
 * validated without needing to query the {@link AuthenticationDao}. It should
 * be noted that if a user appears to present an incorrect password, the
 * {@link AuthenticationDao} will be queried to confirm the most up-to-date
 * password was used for comparison.
 * </p>
 * 
 * <P>
 * If an application context is detected (which is automatically the case when
 * the bean is started within a Spring container), application events will be
 * published to the context. See {@link
 * net.sf.acegisecurity.providers.dao.event.AuthenticationEvent} for further
 * information.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class DaoAuthenticationProvider implements AuthenticationProvider,
    InitializingBean, ApplicationContextAware {
    //~ Instance fields ========================================================

    private ApplicationContext ctx;
    private AuthenticationDao authenticationDao;
    private PasswordEncoder passwordEncoder = new PlaintextPasswordEncoder();
    private SaltSource saltSource;
    private UserCache userCache = new NullUserCache();

    //~ Methods ================================================================

    public void setApplicationContext(ApplicationContext applicationContext)
        throws BeansException {
        this.ctx = applicationContext;
    }

    public void setAuthenticationDao(AuthenticationDao authenticationDao) {
        this.authenticationDao = authenticationDao;
    }

    public AuthenticationDao getAuthenticationDao() {
        return authenticationDao;
    }

    /**
     * Sets the PasswordEncoder instance to be used to encode and validate
     * passwords. If not set, {@link PlaintextPasswordEncoder} will be used by
     * default.
     *
     * @param passwordEncoder The passwordEncoder to use
     */
    public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    public PasswordEncoder getPasswordEncoder() {
        return passwordEncoder;
    }

    /**
     * The source of salts to use when decoding passwords.  <code>null</code>
     * is a valid value, meaning the <code>DaoAuthenticationProvider</code>
     * will present <code>null</code> to the relevant
     * <code>PasswordEncoder</code>.
     *
     * @param saltSource to use when attempting to decode passwords via  the
     *        <code>PasswordEncoder</code>
     */
    public void setSaltSource(SaltSource saltSource) {
        this.saltSource = saltSource;
    }

    public SaltSource getSaltSource() {
        return saltSource;
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
                "An Authentication DAO must be set");
        }

        if (this.userCache == null) {
            throw new IllegalArgumentException("A user cache must be set");
        }
    }

    public Authentication authenticate(Authentication authentication)
        throws AuthenticationException {
        boolean cacheWasUsed = true;
        User user = this.userCache.getUserFromCache(authentication.getPrincipal()
                                                                  .toString());

        if (user == null) {
            cacheWasUsed = false;
            user = getUserFromBackend(authentication);
        }

        if (!user.isEnabled()) {
            if (this.ctx != null) {
                ctx.publishEvent(new AuthenticationFailureDisabledEvent(
                        authentication, user));
            }

            throw new DisabledException("User is disabled");
        }

        if (!isPasswordCorrect(authentication, user)) {
            // Password incorrect, so ensure we're using most current password
            if (cacheWasUsed) {
                cacheWasUsed = false;
                user = getUserFromBackend(authentication);
            }

            if (!isPasswordCorrect(authentication, user)) {
                if (this.ctx != null) {
                    ctx.publishEvent(new AuthenticationFailurePasswordEvent(
                            authentication, user));
                }

                throw new BadCredentialsException("Bad credentials presented");
            }
        }

        if (!cacheWasUsed) {
            // Put into cache
            this.userCache.putUserInCache(user);

            // As this appears to be an initial login, publish the event
            if (this.ctx != null) {
                ctx.publishEvent(new AuthenticationSuccessEvent(
                        authentication, user));
            }
        }

        // Ensure we return the original credentials the user supplied,
        // so subsequent attempts are successful even with encoded passwords
        return new UsernamePasswordAuthenticationToken(user.getUsername(),
            authentication.getCredentials(), user.getAuthorities());
    }

    public boolean supports(Class authentication) {
        if (UsernamePasswordAuthenticationToken.class.isAssignableFrom(
                authentication)) {
            return true;
        } else {
            return false;
        }
    }

    private boolean isPasswordCorrect(Authentication authentication, User user) {
        Object salt = null;

        if (this.saltSource != null) {
            salt = this.saltSource.getSalt(user);
        }

        return passwordEncoder.isPasswordValid(user.getPassword(),
            authentication.getCredentials().toString(), salt);
    }

    private User getUserFromBackend(Authentication authentication) {
        try {
            return this.authenticationDao.loadUserByUsername(authentication.getPrincipal()
                                                                           .toString());
        } catch (UsernameNotFoundException notFound) {
            throw new BadCredentialsException("Bad credentials presented");
        } catch (DataAccessException repositoryProblem) {
            throw new AuthenticationServiceException(repositoryProblem
                .getMessage(), repositoryProblem);
        }
    }
}
