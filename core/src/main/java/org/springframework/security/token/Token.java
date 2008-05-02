package org.springframework.security.token;


/**
 * A token issued by {@link TokenService}.
 * 
 * <p>
 * It is important that the keys assigned to tokens are sufficiently randomised and secured that
 * they can serve as identifying a unique user session. Implementations of {@link TokenService}
 * are free to use encryption or encoding strategies of their choice. It is strongly recommended that
 * keys are of sufficient length to balance safety against persistence cost. In relation to persistence
 * cost, it is strongly recommended that returned keys are small enough for encoding in a cookie.
 * </p>
 * 
 * @author Ben Alex
 * @since 2.0.1
 */
public interface Token {
	
	/**
	 * Obtains the randomised, secure key assigned to this token. Presentation of this token to
	 * {@link TokenService} will always return a <code>Token</code> that is equal to the original
	 * <code>Token</code> issued for that key.
	 * 
	 * @return a key with appropriate randomness and security.
	 */
	String getKey();
	
	/**
	 * The time the token key was initially created is available from this method. Note that a given
	 * token must never have this creation time changed. If necessary, a new token can be
	 * requested from the {@link TokenService} to replace the original token.
	 * 
	 * @return the time this token key was created, in the same format as specified by {@link Date#getTime()).
	 */
	long getKeyCreationTime();	
	
	/**
	 * Obtains the extended information associated within the token, which was presented when the token
	 * was first created.
	 * 
	 * @return the user-specified extended information, if any
	 */
	String getExtendedInformation();
}
