/*
 * Copyright 2004-2021 Acegi Technology Pty Limited
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
 */

package org.springframework.security.web.authentication.rememberme;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Date;
import java.util.Objects;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Identifies previously remembered users by a Base-64 encoded cookie.
 *
 * <p>
 * This implementation does not rely on an external database, so is attractive for simple
 * applications. The cookie will be valid for a specific period from the date of the last
 * {@link #loginSuccess(HttpServletRequest, HttpServletResponse, Authentication)}. As per
 * the interface contract, this method will only be called when the principal completes a
 * successful interactive authentication. As such the time period commences from the last
 * authentication attempt where they furnished credentials - not the time period they last
 * logged in via remember-me. The implementation will only send a remember-me token if the
 * parameter defined by {@link #setParameter(String)} is present.
 * <p>
 * An {@link org.springframework.security.core.userdetails.UserDetailsService} is required
 * by this implementation, so that it can construct a valid <code>Authentication</code>
 * from the returned {@link org.springframework.security.core.userdetails.UserDetails}.
 * This is also necessary so that the user's password is available and can be checked as
 * part of the encoded cookie.
 * <p>
 * The cookie encoded by this implementation adopts either the following form:
 *
 * <pre>
 * username + &quot;:&quot; + expiryTime + &quot;:&quot;
 * 		+ Md5Hex(username + &quot;:&quot; + expiryTime + &quot;:&quot; + password + &quot;:&quot; + key)
 * </pre>
 *
 * or, if a hashing algorithm is configured, the form:
 *
 * <pre>
 * username + &quot;:&quot; + expiryTime + &quot;:&quot; + algorithmName + &quot;:&quot;
 * 		+ hashingAlgorithm(username + &quot;:&quot; + expiryTime + &quot;:&quot; + password + &quot;:&quot; + key)
 * </pre>
 *
 * <p>
 * As such, if the user changes their password, any remember-me token will be invalidated.
 * Equally, the system administrator may invalidate every remember-me token on issue by
 * changing the key. This provides some reasonable approaches to recovering from a
 * remember-me token being left on a public machine (e.g. kiosk system, Internet cafe
 * etc). Most importantly, at no time is the user's password ever sent to the user agent,
 * providing an important security safeguard. Unfortunately the username is necessary in
 * this implementation (as we do not want to rely on a database for remember-me services).
 * High security applications should be aware of this occasionally undesired disclosure of
 * a valid username.
 * <p>
 * The hashing algorithm used, if unspecified, is the MD5 message-digest algorithm in this
 * implementation. If the configured hashing algorithm is changed, existing cookies will
 * still be honored if the key or password are unchanged, but the users' cookies will use
 * the new hashing algorithm the next time they interactively login.
 * <p>
 * This is a basic remember-me implementation which is suitable for many applications.
 * However, we recommend a database-based implementation if you require a more secure
 * remember-me approach (see {@link PersistentTokenBasedRememberMeServices}).
 * <p>
 * By default the tokens will be valid for 14 days from the last successful authentication
 * attempt. This can be changed using {@link #setTokenValiditySeconds(int)}. If this value
 * is less than zero, the <tt>expiryTime</tt> will remain at 14 days, but the negative
 * value will be used for the <tt>maxAge</tt> property of the cookie, meaning that it will
 * not be stored when the browser is closed.
 *
 * @author Ben Alex
 */
public class TokenBasedRememberMeServices extends AbstractRememberMeServices {

	private RememberMeHashingAlgorithm hashingAlgorithm;

	public TokenBasedRememberMeServices(String key, UserDetailsService userDetailsService) {
		this(key, userDetailsService, RememberMeHashingAlgorithm.UNSET);
	}

	/**
	 * @since 5.5
	 */
	public TokenBasedRememberMeServices(String key, UserDetailsService userDetailsService,
			RememberMeHashingAlgorithm hashingAlgorithm) {
		super(key, userDetailsService);
		this.hashingAlgorithm = hashingAlgorithm;
	}

	@Override
	protected UserDetails processAutoLoginCookie(String[] cookieTokens, HttpServletRequest request,
			HttpServletResponse response) {
		if (!(cookieTokens.length == 3 || cookieTokens.length == 4)) {
			throw new InvalidCookieException(
					"Cookie token did not contain 3 or 4 tokens, but contained '" + Arrays.asList(cookieTokens) + "'");
		}
		long tokenExpiryTime = getTokenExpiryTime(cookieTokens);
		if (isTokenExpired(tokenExpiryTime)) {
			throw new InvalidCookieException("Cookie token[1] has expired (expired on '" + new Date(tokenExpiryTime)
					+ "'; current time is '" + new Date() + "')");
		}
		RememberMeHashingAlgorithm algorithm = getTokenHashingAlgorithm(cookieTokens);
		// Check the user exists. Defer lookup until after expiry time checked, to
		// possibly avoid expensive database call.
		UserDetails userDetails = getUserDetailsService().loadUserByUsername(cookieTokens[0]);
		Assert.notNull(userDetails, () -> "UserDetailsService " + getUserDetailsService()
				+ " returned null for username " + cookieTokens[0] + ". " + "This is an interface contract violation");
		// Check signature of token matches remaining details. Must do this after user
		// lookup, as we need the DAO-derived password. If efficiency was a major issue,
		// just add in a UserCache implementation, but recall that this method is usually
		// only called once per HttpSession - if the token is valid, it will cause
		// SecurityContextHolder population, whilst if invalid, will cause the cookie to
		// be cancelled.
		String expectedTokenSignature = makeTokenSignature(tokenExpiryTime, userDetails.getUsername(),
				userDetails.getPassword(), algorithm);
		String tokenSignature = (cookieTokens.length == 4) ? cookieTokens[3] : cookieTokens[2];
		if (!equals(expectedTokenSignature, tokenSignature)) {
			throw new InvalidCookieException("Last Cookie token contained signature '" + tokenSignature
					+ "' but expected '" + expectedTokenSignature + "'");
		}
		return userDetails;
	}

	private long getTokenExpiryTime(String[] cookieTokens) {
		try {
			return new Long(cookieTokens[1]);
		}
		catch (NumberFormatException nfe) {
			throw new InvalidCookieException(
					"Cookie token[1] did not contain a valid number (contained '" + cookieTokens[1] + "')");
		}
	}

	private RememberMeHashingAlgorithm getTokenHashingAlgorithm(String[] cookieTokens) {
		if (cookieTokens.length == 3) {
			return RememberMeHashingAlgorithm.UNSET;
		}
		return RememberMeHashingAlgorithm.findByIdentifier(cookieTokens[2]).orElseThrow(IllegalArgumentException::new);
	}

	/**
	 * Calculates the digital signature expected in the cookie if no algorithm is declared
	 * or configured.
	 *
	 * Default value is MD5("username:tokenExpiryTime:password:key")
	 */
	protected String makeTokenSignature(long tokenExpiryTime, String username, String password) {
		return makeTokenSignature(tokenExpiryTime, username, password, RememberMeHashingAlgorithm.MD5);
	}

	/**
	 * Calculates the digital signature expected in the cookie when a hashing algorithm is
	 * declared or configured.
	 *
	 * Default value is the hashing algorithm applied to
	 * "username:tokenExpiryTime:password:key"
	 * @since 5.5
	 */
	protected String makeTokenSignature(long tokenExpiryTime, String username, String password,
			RememberMeHashingAlgorithm algorithm) {
		if (algorithm == RememberMeHashingAlgorithm.UNSET) {
			return makeTokenSignature(tokenExpiryTime, username, password);
		}
		String data = username + ":" + tokenExpiryTime + ":" + password + ":" + getKey();
		try {
			MessageDigest digest = MessageDigest.getInstance(algorithm.getDigestAlgorithm());
			return new String(Hex.encode(digest.digest(data.getBytes())));
		}
		catch (NoSuchAlgorithmException ex) {
			throw new IllegalStateException("No MD5 algorithm available!");
		}
	}

	protected boolean isTokenExpired(long tokenExpiryTime) {
		return tokenExpiryTime < System.currentTimeMillis();
	}

	@Override
	public void onLoginSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication successfulAuthentication) {
		String username = retrieveUserName(successfulAuthentication);
		String password = retrievePassword(successfulAuthentication);
		// If unable to find a username and password, just abort as
		// TokenBasedRememberMeServices is
		// unable to construct a valid token in this case.
		if (!StringUtils.hasLength(username)) {
			this.logger.debug("Unable to retrieve username");
			return;
		}
		if (!StringUtils.hasLength(password)) {
			UserDetails user = getUserDetailsService().loadUserByUsername(username);
			password = user.getPassword();
			if (!StringUtils.hasLength(password)) {
				this.logger.debug("Unable to obtain password for user: " + username);
				return;
			}
		}
		int tokenLifetime = calculateLoginLifetime(request, successfulAuthentication);
		long expiryTime = System.currentTimeMillis();
		// SEC-949
		expiryTime += 1000L * ((tokenLifetime < 0) ? TWO_WEEKS_S : tokenLifetime);
		String signatureValue = makeTokenSignature(expiryTime, username, password, this.hashingAlgorithm);
		String[] cookieTokens = (this.hashingAlgorithm == RememberMeHashingAlgorithm.UNSET)
				? new String[] { username, Long.toString(expiryTime), signatureValue } : new String[] { username,
						Long.toString(expiryTime), this.hashingAlgorithm.getIdentifier(), signatureValue };
		setCookie(cookieTokens, tokenLifetime, request, response);
		if (this.logger.isDebugEnabled()) {
			this.logger.debug(
					"Added remember-me cookie for user '" + username + "', expiry: '" + new Date(expiryTime) + "'");
		}
	}

	/**
	 * Calculates the validity period in seconds for a newly generated remember-me login.
	 * After this period (from the current time) the remember-me login will be considered
	 * expired. This method allows customization based on request parameters supplied with
	 * the login or information in the <tt>Authentication</tt> object. The default value
	 * is just the token validity period property, <tt>tokenValiditySeconds</tt>.
	 * <p>
	 * The returned value will be used to work out the expiry time of the token and will
	 * also be used to set the <tt>maxAge</tt> property of the cookie.
	 *
	 * See SEC-485.
	 * @param request the request passed to onLoginSuccess
	 * @param authentication the successful authentication object.
	 * @return the lifetime in seconds.
	 */
	protected int calculateLoginLifetime(HttpServletRequest request, Authentication authentication) {
		return getTokenValiditySeconds();
	}

	protected String retrieveUserName(Authentication authentication) {
		if (isInstanceOfUserDetails(authentication)) {
			return ((UserDetails) authentication.getPrincipal()).getUsername();
		}
		return authentication.getPrincipal().toString();
	}

	protected String retrievePassword(Authentication authentication) {
		if (isInstanceOfUserDetails(authentication)) {
			return ((UserDetails) authentication.getPrincipal()).getPassword();
		}
		if (authentication.getCredentials() != null) {
			return authentication.getCredentials().toString();
		}
		return null;
	}

	private boolean isInstanceOfUserDetails(Authentication authentication) {
		return authentication.getPrincipal() instanceof UserDetails;
	}

	/**
	 * Constant time comparison to prevent against timing attacks.
	 */
	private static boolean equals(String expected, String actual) {
		byte[] expectedBytes = bytesUtf8(expected);
		byte[] actualBytes = bytesUtf8(actual);
		return MessageDigest.isEqual(expectedBytes, actualBytes);
	}

	private static byte[] bytesUtf8(String s) {
		return (s != null) ? Utf8.encode(s) : null;
	}

	/**
	 * @since 5.5
	 */
	public RememberMeHashingAlgorithm getHashAlgorithm() {
		return this.hashingAlgorithm;
	}

	/**
	 * Sets the hashing algorithm used in new cookies
	 * @throws NullPointerException when the algorithm is null
	 * @since 5.5
	 */
	public void setHashAlgorithm(RememberMeHashingAlgorithm hashingAlgorithm) {
		this.hashingAlgorithm = Objects.requireNonNull(hashingAlgorithm);
	}

}
