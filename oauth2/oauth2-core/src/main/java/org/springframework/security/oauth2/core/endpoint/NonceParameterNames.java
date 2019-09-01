package org.springframework.security.oauth2.core.endpoint;

/**
 * Standard parameter names defined in the OpenID Connect Core 1.0
 * incorporating errata set 1 and used by the authorization endpoint and
 * token endpoint.
 *
 * @author Mark Heckler
 * @since 5.2
 * @see <a target="_blank" href="https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes">15.5.2.  Nonce Implementation Notes</a>
 */
public interface NonceParameterNames {
	/**
	 * {@code nonce} - used in Authentication Request.
	 */
	String NONCE = "nonce";
}
