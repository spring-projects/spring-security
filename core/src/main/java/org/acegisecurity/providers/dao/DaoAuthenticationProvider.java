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

import org.springframework.beans.factory.InitializingBean;

import org.springframework.dao.DataAccessException;


/**
 * An {@link AuthenticationProvider} implementation that retrieves user details
 * from an {@link AuthenticationDao}.
 * 
 * <p>
 * This <code>AuthenticationProvider</code> is capable of validating  {@link
 * UsernamePasswordAuthenticationToken} requests contain the correct username,
 * password and the user is not disabled.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class DaoAuthenticationProvider implements AuthenticationProvider,
    InitializingBean {
    //~ Instance fields ========================================================

    private AuthenticationDao authenticationDao;
    private PasswordEncoder passwordEncoder = new PlaintextPasswordEncoder();

    //~ Methods ================================================================

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

    public void afterPropertiesSet() throws Exception {
        if (this.authenticationDao == null) {
            throw new IllegalArgumentException(
                "An Authentication DAO must be set");
        }
    }

    public Authentication authenticate(Authentication authentication)
        throws AuthenticationException {
        User user = null;

        try {
            user = this.authenticationDao.loadUserByUsername(authentication.getPrincipal()
                                                                           .toString());
        } catch (UsernameNotFoundException notFound) {
            throw new BadCredentialsException("Bad credentials presented");
        } catch (DataAccessException repositoryProblem) {
            throw new AuthenticationServiceException(repositoryProblem
                .getMessage(), repositoryProblem);
        }

        if (!passwordEncoder.isPasswordValid(user.getPassword(),
                authentication.getCredentials().toString(), user))
            throw new BadCredentialsException("Bad credentials presented");

        if (!user.isEnabled()) {
            throw new DisabledException("User is disabled");
        }

        return new UsernamePasswordAuthenticationToken(user.getUsername(),
            authentication.getCredentials().toString(), user.getAuthorities());
    }

    public boolean supports(Class authentication) {
        if (UsernamePasswordAuthenticationToken.class.isAssignableFrom(
                authentication)) {
            return true;
        } else {
            return false;
        }
    }
}
