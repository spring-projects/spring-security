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

import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.BadCredentialsException;

import org.acegisecurity.providers.AuthenticationProvider;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.encoding.PasswordEncoder;
import org.acegisecurity.providers.encoding.PlaintextPasswordEncoder;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;

import org.springframework.dao.DataAccessException;

import org.springframework.util.Assert;


/**
 * An {@link AuthenticationProvider} implementation that retrieves user details
 * from an {@link UserDetailsService}.
 */
public class DaoAuthenticationProvider
    extends AbstractUserDetailsAuthenticationProvider {
    //~ Instance fields ========================================================

    private UserDetailsService userDetailsService;
    private PasswordEncoder passwordEncoder = new PlaintextPasswordEncoder();
    private SaltSource saltSource;
    private boolean hideUserNotFoundExceptions = true;

    //~ Methods ================================================================

    protected void additionalAuthenticationChecks(UserDetails userDetails,
        UsernamePasswordAuthenticationToken authentication)
        throws AuthenticationException {
        Object salt = null;

        if (this.saltSource != null) {
            salt = this.saltSource.getSalt(userDetails);
        }

        if (!passwordEncoder.isPasswordValid(userDetails.getPassword(),
                authentication.getCredentials().toString(), salt)) {
            throw new BadCredentialsException(messages.getMessage(
                    "AbstractUserDetailsAuthenticationProvider.badCredentials",
                    "Bad credentials"), userDetails);
        }
    }

    protected void doAfterPropertiesSet() throws Exception {
        Assert.notNull(this.userDetailsService,
            "An Authentication DAO must be set");
    }

    public UserDetailsService getUserDetailsService() {
        return userDetailsService;
    }

    public PasswordEncoder getPasswordEncoder() {
        return passwordEncoder;
    }

    public SaltSource getSaltSource() {
        return saltSource;
    }

    public boolean isHideUserNotFoundExceptions() {
        return hideUserNotFoundExceptions;
    }

    protected final UserDetails retrieveUser(String username,
        UsernamePasswordAuthenticationToken authentication)
        throws AuthenticationException {
        UserDetails loadedUser;

        try {
            loadedUser = this.userDetailsService.loadUserByUsername(username);
        } catch (UsernameNotFoundException notFound) {
            if (hideUserNotFoundExceptions) {
                throw new BadCredentialsException(messages.getMessage(
                        "AbstractUserDetailsAuthenticationProvider.badCredentials",
                        "Bad credentials"));
            } else {
                throw notFound;
            }
        } catch (DataAccessException repositoryProblem) {
            throw new AuthenticationServiceException(repositoryProblem
                    .getMessage(), repositoryProblem);
            }

            if (loadedUser == null) {
                throw new AuthenticationServiceException(
                    "AuthenticationDao returned null, which is an interface contract violation");
            }

            return loadedUser;
        }

        public void setUserDetailsService(UserDetailsService authenticationDao) {
            this.userDetailsService = authenticationDao;
        }

        /**
         * By default the <code>DaoAuthenticationProvider</code> throws a
         * <code>BadCredentialsException</code> if a username is not found or
         * the password is incorrect. Setting this property to
         * <code>false</code> will cause
         * <code>UsernameNotFoundException</code>s to be thrown instead for
         * the former. Note this is considered less secure than throwing
         * <code>BadCredentialsException</code> for both exceptions.
         *
         * @param hideUserNotFoundExceptions set to <code>false</code> if you
         *        wish <code>UsernameNotFoundException</code>s to be thrown
         *        instead of the non-specific
         *        <code>BadCredentialsException</code> (defaults to
         *        <code>true</code>)
         */
        public void setHideUserNotFoundExceptions(
            boolean hideUserNotFoundExceptions) {
            this.hideUserNotFoundExceptions = hideUserNotFoundExceptions;
        }

        /**
         * Sets the PasswordEncoder instance to be used to encode and validate
         * passwords. If not set, {@link PlaintextPasswordEncoder} will be
         * used by default.
         *
         * @param passwordEncoder The passwordEncoder to use
         */
        public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
            this.passwordEncoder = passwordEncoder;
        }

        /**
         * The source of salts to use when decoding passwords.
         * <code>null</code> is a valid value, meaning the
         * <code>DaoAuthenticationProvider</code> will present
         * <code>null</code> to the relevant <code>PasswordEncoder</code>.
         *
         * @param saltSource to use when attempting to decode passwords via the
         *        <code>PasswordEncoder</code>
         */
        public void setSaltSource(SaltSource saltSource) {
            this.saltSource = saltSource;
        }
    }
