package org.springframework.security.oauth2.jwt;

import com.nimbusds.jose.JOSEObject;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import net.minidev.json.JSONObject;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.text.ParseException;
import java.util.Map;

public class MultiTenantDelegatingJwtDecoder implements JwtDecoder {
	private static final String DECODING_ERROR_MESSAGE_TEMPLATE =
			"An error occurred while attempting to decode the Jwt: %s";

	private JwtDecoder decoderDefault;

	private Map<String, JwtDecoder> decoderByIssuer;

	public MultiTenantDelegatingJwtDecoder(JwtDecoder decoderDefault) {
		this(decoderDefault, null);
	}

	public MultiTenantDelegatingJwtDecoder(
			Map<String, JwtDecoder> decoderByIssuer) {
		this(null, decoderByIssuer);
	}

	public MultiTenantDelegatingJwtDecoder(
			JwtDecoder decoderDefault,
			Map<String, JwtDecoder> decoderByIssuer) {
		Assert.isTrue(decoderDefault != null || !CollectionUtils.isEmpty(decoderByIssuer),
				"At least one of decoderDefault or decoderByIssuer must be provided");
		this.decoderDefault = decoderDefault;
		this.decoderByIssuer = decoderByIssuer;
	}

	@Override
	public Jwt decode(String token) throws JwtException {
		JwtDecoder jwtDecoder = null;
		if (!CollectionUtils.isEmpty(decoderByIssuer)) {
			String issuer = parseAndFindIssuer(token);
			if (issuer == null && decoderDefault == null) {
				throw new JwtException(
						"Unable to determine issuer for the token");
			} else {
				jwtDecoder = decoderByIssuer.get(issuer);
				if (jwtDecoder == null && decoderDefault == null) {
					throw new JwtException(String.format(
							"JwtDecoder has not been configured for issuer %s", issuer));
				}
			}
		}
		if (jwtDecoder == null && decoderDefault != null) {
			jwtDecoder = decoderDefault;
		} else {
			throw new JwtException(String.format("Unable to determine JwtDecoder"));
		}
		return jwtDecoder.decode(token);
	}

	private String parseAndFindIssuer(String token) {
		try {
			Base64URL[] parts = JOSEObject.split(token);
			JSONObject payload = JSONObjectUtils.parse(parts[1].decodeToString());
			return payload.getAsString("iss");
		} catch (ArrayIndexOutOfBoundsException
				| NullPointerException
				| ParseException ex) {
			throw new JwtException(String.format(
					DECODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
		}
	}

}
