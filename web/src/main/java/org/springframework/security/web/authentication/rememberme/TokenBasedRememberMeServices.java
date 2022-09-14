/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

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
 * The cookie encoded by this implementation adopts the following form:
 *
 * <pre>
 * username + &quot;:&quot; + expiryTime + &quot;:&quot; + algorithmName + &quot;:&quot;
 * 		+ algorithmHex(username + &quot;:&quot; + expiryTime + &quot;:&quot; + password + &quot;:&quot; + key)
 * </pre>
 *
 * <p>
 * This implementation uses the algorithm configured in {@link #encodingAlgorithm} to
 * encode the signature. It will try to use the algorithm retrieved from the
 * {@code algorithmName} to validate the signature. However, if the {@code algorithmName}
 * is not present in the cookie value, the algorithm configured in
 * {@link #matchingAlgorithm} will be used to validate the signature. This allows users to
 * safely upgrade to a different encoding algorithm while still able to verify old ones if
 * there is no {@code algorithmName} present.
 * </p>
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
 * @author Marcus Da Coregio
 */
public class TokenBasedRememberMeServices extends AbstractRememberMeServices {

	private static final RememberMeTokenAlgorithm DEFAULT_MATCHING_ALGORITHM = RememberMeTokenAlgorithm.SHA256;

	private static final RememberMeTokenAlgorithm DEFAULT_ENCODING_ALGORITHM = RememberMeTokenAlgorithm.SHA256;

	private final RememberMeTokenAlgorithm encodingAlgorithm;

	private RememberMeTokenAlgorithm matchingAlgorithm = DEFAULT_MATCHING_ALGORITHM;

	public TokenBasedRememberMeServices(String key, UserDetailsService userDetailsService) {
		this(key, userDetailsService, DEFAULT_ENCODING_ALGORITHM);
	}

	/**
	 * Construct the instance with the parameters provided
	 * @param key the signature key
	 * @param userDetailsService the {@link UserDetailsService}
	 * @param encodingAlgorithm the {@link RememberMeTokenAlgorithm} used to encode the
	 * signature
	 * @since 5.8
	 */
	public TokenBasedRememberMeServices(String key, UserDetailsService userDetailsService,
			RememberMeTokenAlgorithm encodingAlgorithm) {
		super(key, userDetailsService);
		Assert.notNull(encodingAlgorithm, "encodingAlgorithm cannot be null");
		this.encodingAlgorithm = encodingAlgorithm;
	}

	@Override
	protected UserDetails processAutoLoginCookie(String[] cookieTokens, HttpServletRequest request,
			HttpServletResponse response) {
		if (!isValidCookieTokensLength(cookieTokens)) {
			throw new InvalidCookieException(
					"Cookie token did not contain 3 or 4 tokens, but contained '" + Arrays.asList(cookieTokens) + "'");
		}
		long tokenExpiryTime = getTokenExpiryTime(cookieTokens);
		if (isTokenExpired(tokenExpiryTime)) {
			throw new InvalidCookieException("Cookie token[1] has expired (expired on '" + new Date(tokenExpiryTime)
					+ "'; current time is '" + new Date() + "')");
		}
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
		String actualTokenSignature = cookieTokens[2];
		RememberMeTokenAlgorithm actualAlgorithm = this.matchingAlgorithm;
		// If the cookie value contains the algorithm, we use that algorithm to check the
		// signature
		if (cookieTokens.length == 4) {
			actualTokenSignature = cookieTokens[3];
			actualAlgorithm = RememberMeTokenAlgorithm.valueOf(cookieTokens[2]);
		}
		String expectedTokenSignature = makeTokenSignature(tokenExpiryTime, userDetails.getUsername(),
				userDetails.getPassword(), actualAlgorithm);
		if (!equals(expectedTokenSignature, actualTokenSignature)) {
			throw new InvalidCookieException("Cookie contained signature '" + actualTokenSignature + "' but expected '"
					+ expectedTokenSignature + "'");
		}
		return userDetails;
	}

	private boolean isValidCookieTokensLength(String[] cookieTokens) {
		return cookieTokens.length == 3 || cookieTokens.length == 4;
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

	/**
	 * Calculates the digital signature to be put in the cookie. Default value is
	 * {@link #encodingAlgorithm} applied to ("username:tokenExpiryTime:password:key")
	 */
	protected String makeTokenSignature(long tokenExpiryTime, String username, String password) {
		String data = username + ":" + tokenExpiryTime + ":" + password + ":" + getKey();
		try {
			MessageDigest digest = MessageDigest.getInstance(this.encodingAlgorithm.getDigestAlgorithm());
			return new String(Hex.encode(digest.digest(data.getBytes())));
		}
		catch (NoSuchAlgorithmException ex) {
			throw new IllegalStateException("No " + this.encodingAlgorithm.name() + " algorithm available!");
		}
	}

	/**
	 * Calculates the digital signature to be put in the cookie.
	 * @since 5.8
	 */
	protected String makeTokenSignature(long tokenExpiryTime, String username, String password,
			RememberMeTokenAlgorithm algorithm) {
		String data = username + ":" + tokenExpiryTime + ":" + password + ":" + getKey();
		try {
			MessageDigest digest = MessageDigest.getInstance(algorithm.getDigestAlgorithm());
			return new String(Hex.encode(digest.digest(data.getBytes())));
		}
		catch (NoSuchAlgorithmException ex) {
			throw new IllegalStateException("No " + algorithm.name() + " algorithm available!");
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
		String signatureValue = makeTokenSignature(expiryTime, username, password, this.encodingAlgorithm);
		setCookie(new String[] { username, Long.toString(expiryTime), this.encodingAlgorithm.name(), signatureValue },
				tokenLifetime, request, response);
		if (this.logger.isDebugEnabled()) {
			this.logger.debug(
					"Added remember-me cookie for user '" + username + "', expiry: '" + new Date(expiryTime) + "'");
		}
	}

	/**
	 * Sets the algorithm to be used to match the token signature
	 * @param matchingAlgorithm the matching algorithm
	 * @since 5.8
	 */
	public void setMatchingAlgorithm(RememberMeTokenAlgorithm matchingAlgorithm) {
		Assert.notNull(matchingAlgorithm, "matchingAlgorithm cannot be null");
		this.matchingAlgorithm = matchingAlgorithm;
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
	 * <p>
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

	public enum RememberMeTokenAlgorithm {

		MD5("MD5"), SHA256("SHA-256");

		private final String digestAlgorithm;

		RememberMeTokenAlgorithm(String digestAlgorithm) {
			this.digestAlgorithm = digestAlgorithm;
		}

		public String getDigestAlgorithm() {
			return this.digestAlgorithm;
		}

	}

}
