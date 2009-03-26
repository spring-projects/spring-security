package org.springframework.security.web.authentication.rememberme;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.springframework.dao.DataAccessException;
import org.springframework.security.Authentication;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.util.Assert;

/**
 * {@link RememberMeServices} implementation based on Barry Jaspan's
 * <a href="http://jaspan.com/improved_persistent_login_cookie_best_practice">Improved Persistent Login Cookie
 * Best Practice</a>.
 *
 * There is a slight modification to the described approach, in that the username is not stored as part of the cookie
 * but obtained from the persistent store via an implementation of {@link PersistentTokenRepository}. The latter
 * should place a unique constraint on the series identifier, so that it is impossible for the same identifier to be
 * allocated to two different users.
 *
 * <p>User management such as changing passwords, removing users and setting user status should be combined
 * with maintenance of the user's persistent tokens.
 * </p>
 *
 * <p>Note that while this class will use the date a token was created to check whether a presented cookie
 * is older than the configured <tt>tokenValiditySeconds</tt> property and deny authentication in this case,
 * it will not delete these tokens from storage. A suitable batch process should be run periodically to
 * remove expired tokens from the database.
 * </p>
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.0
 */
public class PersistentTokenBasedRememberMeServices extends AbstractRememberMeServices {

    private PersistentTokenRepository tokenRepository = new InMemoryTokenRepositoryImpl();
    private SecureRandom random;

    public static final int DEFAULT_SERIES_LENGTH = 16;
    public static final int DEFAULT_TOKEN_LENGTH = 16;

    private int seriesLength = DEFAULT_SERIES_LENGTH;
    private int tokenLength = DEFAULT_TOKEN_LENGTH;

    public PersistentTokenBasedRememberMeServices() throws Exception {
        random = SecureRandom.getInstance("SHA1PRNG");
    }

    /**
     * Locates the presented cookie data in the token repository, using the series id.
     * If the data compares successfully with that in the persistent store, a new token is generated and stored with
     * the same series. The corresponding cookie value is set on the response.
     *
     * @param cookieTokens the series and token values
     *
     * @throws RememberMeAuthenticationException if there is no stored token corresponding to the submitted cookie, or
     * if the token in the persistent store has expired.
     * @throws InvalidCookieException if the cookie doesn't have two tokens as expected.
     * @throws CookieTheftException if a presented series value is found, but the stored token is different from the
     * one presented.
     */
    protected UserDetails processAutoLoginCookie(String[] cookieTokens, HttpServletRequest request, HttpServletResponse response) {

        if (cookieTokens.length != 2) {
            throw new InvalidCookieException("Cookie token did not contain " + 2 +
                    " tokens, but contained '" + Arrays.asList(cookieTokens) + "'");
        }

        final String presentedSeries = cookieTokens[0];
        final String presentedToken = cookieTokens[1];

        PersistentRememberMeToken token = tokenRepository.getTokenForSeries(presentedSeries);

        if (token == null) {
            // No series match, so we can't authenticate using this cookie
            throw new RememberMeAuthenticationException("No persistent token found for series id: " + presentedSeries);
        }

        // We have a match for this user/series combination
        if (!presentedToken.equals(token.getTokenValue())) {
            // Token doesn't match series value. Delete all logins for this user and throw an exception to warn them.
            tokenRepository.removeUserTokens(token.getUsername());

            throw new CookieTheftException(messages.getMessage("PersistentTokenBasedRememberMeServices.cookieStolen",
                    "Invalid remember-me token (Series/token) mismatch. Implies previous cookie theft attack."));
        }

        if (token.getDate().getTime() + getTokenValiditySeconds()*1000 < System.currentTimeMillis()) {
            throw new RememberMeAuthenticationException("Remember-me login has expired");
        }

        // Token also matches, so login is valid. Update the token value, keeping the *same* series number.
        if (logger.isDebugEnabled()) {
            logger.debug("Refreshing persistent login token for user '" + token.getUsername() + "', series '" +
                    token.getSeries() + "'");
        }

        PersistentRememberMeToken newToken = new PersistentRememberMeToken(token.getUsername(),
                token.getSeries(), generateTokenData(), new Date());

        try {
            tokenRepository.updateToken(newToken.getSeries(), newToken.getTokenValue(), newToken.getDate());
            addCookie(newToken, request, response);
        } catch (DataAccessException e) {
            logger.error("Failed to update token: ", e);
            throw new RememberMeAuthenticationException("Autologin failed due to data access problem");
        }

        UserDetails user = getUserDetailsService().loadUserByUsername(token.getUsername());

        return user;
    }

    /**
     * Creates a new persistent login token with a new series number, stores the data in the
     * persistent token repository and adds the corresponding cookie to the response.
     *
     */
    protected void onLoginSuccess(HttpServletRequest request, HttpServletResponse response, Authentication successfulAuthentication) {
        String username = successfulAuthentication.getName();

        logger.debug("Creating new persistent login for user " + username);

        PersistentRememberMeToken persistentToken = new PersistentRememberMeToken(username, generateSeriesData(),
                generateTokenData(), new Date());
        try {
            tokenRepository.createNewToken(persistentToken);
            addCookie(persistentToken, request, response);
        } catch (DataAccessException e) {
            logger.error("Failed to save persistent token ", e);

        }
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        super.logout(request, response, authentication);
        tokenRepository.removeUserTokens(authentication.getName());
    }

    protected String generateSeriesData() {
        byte[] newSeries = new byte[seriesLength];
        random.nextBytes(newSeries);
        return new String(Base64.encodeBase64(newSeries));
    }

    protected String generateTokenData() {
        byte[] newToken = new byte[tokenLength];
        random.nextBytes(newToken);
        return new String(Base64.encodeBase64(newToken));
    }

    private void addCookie(PersistentRememberMeToken token, HttpServletRequest request, HttpServletResponse response) {
        setCookie(new String[] {token.getSeries(), token.getTokenValue()},getTokenValiditySeconds(), request, response);
    }

    public void setTokenRepository(PersistentTokenRepository tokenRepository) {
        this.tokenRepository = tokenRepository;
    }

    public void setSeriesLength(int seriesLength) {
        this.seriesLength = seriesLength;
    }

    public void setTokenLength(int tokenLength) {
        this.tokenLength = tokenLength;
    }

    @Override
    public void setTokenValiditySeconds(int tokenValiditySeconds) {
        Assert.isTrue(tokenValiditySeconds > 0, "tokenValiditySeconds must be positive for this implementation");
        super.setTokenValiditySeconds(tokenValiditySeconds);
    }
}
