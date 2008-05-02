package org.springframework.security.token;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;
import java.util.Date;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.util.Sha512DigestUtils;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Basic implementation of {@link TokenService} that is compatible with clusters and across machine restarts,
 * without requiring database persistence.
 * 
 * <p>
 * Keys are produced in the format:
 * </p>
 * 
 * <p>
 * Base64(creationTime + ":" + hex(pseudoRandomNumber) + ":" + extendedInformation + ":" +
 * Sha512Hex(creationTime + ":" + hex(pseudoRandomNumber) + ":" + extendedInformation + ":" + serverSecret) )
 * </p>
 * 
 * <p>
 * In the above, <code>creationTime</code>, <code>tokenKey</code> and <code>extendedInformation</code>
 * are equal to that stored in {@link Token}. The <code>Sha512Hex</code> includes the same payload,
 * plus a <code>serverSecret</code>.
 * </p>
 * 
 * <p>
 * The <code>serverSecret</code> varies every millisecond. It relies on two static server-side secrets. The first
 * is a password, and the second is a server integer. Both of these must remain the same for any issued keys
 * to subsequently be recognised. The applicable <code>serverSecret</code> in any millisecond is computed by
 * <code>password</code> + ":" + (<code>creationTime</code> % <code>serverInteger</code>). This approach
 * further obfuscates the actual server secret and renders attempts to compute the server secret more
 * limited in usefulness (as any false tokens would be forced to have a <code>creationTime</code> equal
 * to the computed hash). Recall that framework features depending on token services should reject tokens
 * that are relatively old in any event.
 * </p>
 * 
 * <p>
 * A further consideration of this class is the requirement for cryptographically strong pseudo-random numbers.
 * To this end, the use of {@link SecureRandomFactoryBean} is recommended to inject the property.
 * </p>
 *
 * <p>
 * This implementation uses UTF-8 encoding internally for string manipulation.
 * </p>
 * 
 * @author Ben Alex
 *
 */
public class KeyBasedPersistenceTokenService implements TokenService, InitializingBean {
	private int pseudoRandomNumberBits = 256;
	private String serverSecret;
	private Integer serverInteger;
	private SecureRandom secureRandom;
	
	public Token allocateToken(String extendedInformation) {
		Assert.notNull(extendedInformation, "Must provided non-null extendedInformation (but it can be empty)");
		long creationTime = new Date().getTime();
		String serverSecret = computeServerSecretApplicableAt(creationTime);
		String pseudoRandomNumber = generatePseudoRandomNumber();
		String content = new Long(creationTime).toString() + ":" + pseudoRandomNumber + ":" + extendedInformation;

		// Compute key
		String sha512Hex = Sha512DigestUtils.shaHex(content + ":" + serverSecret);
		String keyPayload = content + ":" + sha512Hex;
		String key = convertToString(Base64.encodeBase64(convertToBytes(keyPayload)));
		
		return new DefaultToken(key, creationTime, extendedInformation);
	}

	public Token verifyToken(String key) {
		if (key == null || "".equals(key)) {
			return null;
		}
		String[] tokens = StringUtils.delimitedListToStringArray(convertToString(Base64.decodeBase64(convertToBytes(key))), ":");
		Assert.isTrue(tokens.length >= 4, "Expected 4 or more tokens but found " + tokens.length);
		
		long creationTime;
		try {
			creationTime = Long.decode(tokens[0]).longValue();
		} catch (NumberFormatException nfe) {
			throw new IllegalArgumentException("Expected number but found " + tokens[0]);
		}
		
		String serverSecret = computeServerSecretApplicableAt(creationTime);
		String pseudoRandomNumber = tokens[1];
		
		// Permit extendedInfo to itself contain ":" characters
		StringBuffer extendedInfo = new StringBuffer();
		for (int i = 2; i < tokens.length-1; i++) {
			if (i > 2) {
				extendedInfo.append(":");
			}
			extendedInfo.append(tokens[i]);
		}
		
		String sha1Hex = tokens[tokens.length-1];
		
		// Verification
		String content = new Long(creationTime).toString() + ":" + pseudoRandomNumber + ":" + extendedInfo.toString();
		String expectedSha512Hex = Sha512DigestUtils.shaHex(content + ":" + serverSecret);
		Assert.isTrue(expectedSha512Hex.equals(sha1Hex), "Key verification failure");
		
		return new DefaultToken(key, creationTime, extendedInfo.toString());
	}
	
	private byte[] convertToBytes(String input) {
		try {
			return input.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
	}
	
	private String convertToString(byte[] bytes) {
		try {
			return new String(bytes, "UTF-8");
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	/**
	 * @return a pseduo random number (hex encoded)
	 */
	private String generatePseudoRandomNumber() {
		byte[] randomizedBits = new byte[pseudoRandomNumberBits];
		secureRandom.nextBytes(randomizedBits);
		return new String(Hex.encodeHex(randomizedBits));
	}
	
	private String computeServerSecretApplicableAt(long time) {
		return serverSecret + ":" + new Long(time % serverInteger.intValue()).intValue();
	}

	/**
	 * @param serverSecret the new secret, which can contain a ":" if desired (never being sent to the client)
	 */
	public void setServerSecret(String serverSecret) {
		this.serverSecret = serverSecret;
	}
	
	public void setSecureRandom(SecureRandom secureRandom) {
		this.secureRandom = secureRandom;
	}
	
	/**
	 * @param pseudoRandomNumberBits changes the number of bits issued (must be >= 0; defaults to 256)
	 */
	public void setPseudoRandomNumberBits(int pseudoRandomNumberBits) {
		Assert.isTrue(pseudoRandomNumberBits >= 0, "Must have a positive pseudo random number bit size");
		this.pseudoRandomNumberBits = pseudoRandomNumberBits;
	}

	public void setServerInteger(Integer serverInteger) {
		this.serverInteger = serverInteger;
	}

	public void afterPropertiesSet() throws Exception {
		Assert.hasText(serverSecret, "Server secret required");
		Assert.notNull(serverInteger, "Server integer required");
		Assert.notNull(secureRandom, "SecureRandom instance required");
	}
}
