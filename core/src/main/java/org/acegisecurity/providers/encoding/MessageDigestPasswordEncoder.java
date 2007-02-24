package org.acegisecurity.providers.encoding;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Base for digest password encoders.
 * <p>This class can be used stand-alone, or one of the subclasses can be used for compatiblity and convenience.
 * When using this class directly you must specify a
 * <a href="http://java.sun.com/j2se/1.4.2/docs/guide/security/CryptoSpec.html#AppA">
 * Message Digest Algorithm</a> to use as a constructor arg</p>
 *
 * <p>The encoded password hash is normally returned as Hex (32 char) version of the hash bytes.
 * Setting the <tt>encodeHashAsBase64</tt> property to <tt>true</tt> will cause the encoded pass to be returned
 * as Base64 text, which will consume 24 characters.
 * See {@link BaseDigestPasswordEncoder#setEncodeHashAsBase64(boolean)}
 * </p>
 * <p>
 * This PasswordEncoder can be used directly as in the following example:<br/>
 * <pre>
 * &lt;bean id="passwordEncoder" class="org.acegisecurity.providers.encoding.MessageDigestPasswordEncoder"&gt;
 *     &lt;constructor-arg value="MD5"/&gt;
 * &lt;/bean&gt;
 * </pre>
 * </p>
 *
 * @author Ray Krueger
 * @since 1.0.1
 */
public class MessageDigestPasswordEncoder extends BaseDigestPasswordEncoder {

    private final String algorithm;

    /**
     * The digest algorithm to use
     * Supports the named <a href="http://java.sun.com/j2se/1.4.2/docs/guide/security/CryptoSpec.html#AppA">
     * Message Digest Algorithms</a> in the Java environment.
     *
     * @param algorithm
     */
    public MessageDigestPasswordEncoder(String algorithm) {
        this(algorithm, false);
    }

    /**
     * Convenience constructor for specifying the algorithm and whether or not to enable base64 encoding
     *
     * @param algorithm
     * @param encodeHashAsBase64
     * @throws IllegalArgumentException if an unknown
     */
    public MessageDigestPasswordEncoder(String algorithm, boolean encodeHashAsBase64) throws IllegalArgumentException {
        this.algorithm = algorithm;
        setEncodeHashAsBase64(encodeHashAsBase64);
        //Validity Check
        getMessageDigest();
    }

    /**
     * Encodes the rawPass using a MessageDigest.
     * If a salt is specified it will be merged with the password before encoding.
     *
     * @param rawPass The plain text password
     * @param salt The salt to sprinkle
     * @return Hex string of password digest (or base64 encoded string if encodeHashAsBase64 is enabled.
     */
    public String encodePassword(String rawPass, Object salt) {
        String saltedPass = mergePasswordAndSalt(rawPass, salt, false);

        MessageDigest messageDigest = getMessageDigest();

        byte[] digest = messageDigest.digest(saltedPass.getBytes());

        if (getEncodeHashAsBase64()) {
            return new String(Base64.encodeBase64(digest));
        } else {
            return new String(Hex.encodeHex(digest));
        }
    }

    /**
     * Get a MessageDigest instance for the given algorithm.
     * Throws an IllegalArgumentException if <i>algorithm</i> is unknown
     *
     * @return MessageDigest instance
     * @throws IllegalArgumentException if NoSuchAlgorithmException is thrown
     */
    protected final MessageDigest getMessageDigest() throws IllegalArgumentException {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("No such algorithm [" + algorithm + "]");
        }
    }

    /**
     * Takes a previously encoded password and compares it with a rawpassword after mixing in the salt and
     * encoding that value
     *
     * @param encPass previously encoded password
     * @param rawPass plain text password
     * @param salt salt to mix into password
     * @return true or false
     */
    public boolean isPasswordValid(String encPass, String rawPass, Object salt) {
        String pass1 = "" + encPass;
        String pass2 = encodePassword(rawPass, salt);

        return pass1.equals(pass2);
    }

    public String getAlgorithm() {
        return algorithm;
    }
}
