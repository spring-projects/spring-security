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
import net.sf.acegisecurity.providers.encoding.PasswordEncoder;
import net.sf.acegisecurity.providers.encoding.PlaintextPasswordEncoder;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.dao.DataAccessException;

import java.util.Date;


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
 * <p>
 * Upon successful validation, a <code>DaoAuthenticationToken</code> will be
 * created and returned to the caller. This token will be signed with the key
 * configured by {@link #getKey()} and expire {@link
 * #getRefreshTokenInterval()} milliseconds into the future. The token will be
 * assumed to remain valid whilstever it has not expired, and no requests of
 * the <code>AuthenticationProvider</code> will need to be made. Once the
 * token has expired, the relevant <code>AuthenticationProvider</code> will be
 * called again to provide an updated enabled/disabled status, and list of
 * granted authorities. It should be noted the credentials will not be
 * revalidated, as the user presented correct credentials in the originial
 * <code>UsernamePasswordAuthenticationToken</code>. This avoids complications
 * if the user changes their password during the session.
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
    private SaltSource saltSource;
    private String key;
    private long refreshTokenInterval = 60000; // 60 seconds

    //~ Methods ================================================================

    public void setAuthenticationDao(AuthenticationDao authenticationDao) {
        this.authenticationDao = authenticationDao;
    }

    public AuthenticationDao getAuthenticationDao() {
        return authenticationDao;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getKey() {
        return key;
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

    public void setRefreshTokenInterval(long refreshTokenInterval) {
        this.refreshTokenInterval = refreshTokenInterval;
    }

    /**
     * Indicates the number of seconds a created
     * <code>DaoAuthenticationToken</code> will remain valid for. Whilstever
     * the token is valid, the <code>DaoAuthenticationProvider</code> will
     * only check it presents the expected key hash code.
     *
     * @return Returns the refreshTokenInterval.
     */
    public long getRefreshTokenInterval() {
        return refreshTokenInterval;
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

    public void afterPropertiesSet() throws Exception {
        if (this.authenticationDao == null) {
            throw new IllegalArgumentException(
                "An Authentication DAO must be set");
        }

        if ((this.key == null) || "".equals(key)) {
            throw new IllegalArgumentException("A key must be set");
        }
    }

    public Authentication authenticate(Authentication authentication)
        throws AuthenticationException {
        // If an existing DaoAuthenticationToken, check we created it and it hasn't expired
        if (authentication instanceof DaoAuthenticationToken) {
            if (this.key.hashCode() == ((DaoAuthenticationToken) authentication)
                .getKeyHash()) {
                if (((DaoAuthenticationToken) authentication).getExpires()
                     .after(new Date())) {
                    return authentication;
                }
            } else {
                throw new BadCredentialsException(
                    "The presented DaoAuthenticationToken does not contain the expected key");
            }
        }

        // We need to authenticate or refresh the token
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

        if (!(authentication instanceof DaoAuthenticationToken)) {
            // Must validate credentials, as this is not simply a token refresh
            Object salt = null;

            if (this.saltSource != null) {
                salt = this.saltSource.getSalt(user);
            }

            if (!passwordEncoder.isPasswordValid(user.getPassword(),
                    authentication.getCredentials().toString(), salt)) {
                throw new BadCredentialsException("Bad credentials presented");
            }
        }

        if (!user.isEnabled()) {
            throw new DisabledException("User is disabled");
        }

        Date expiry = new Date(new Date().getTime()
                + this.getRefreshTokenInterval());

        return new DaoAuthenticationToken(this.getKey(), expiry,
            user.getUsername(), user.getPassword(), user.getAuthorities());
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
