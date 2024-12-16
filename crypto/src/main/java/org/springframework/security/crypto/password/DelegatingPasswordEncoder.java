/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.crypto.password;

import java.util.HashMap;
import java.util.Map;

import org.springframework.util.StringUtils;

/**
 * A password encoder that delegates to another PasswordEncoder based upon a prefixed
 * identifier.
 *
 * <h2>Constructing an instance</h2>
 *
 * You can easily construct an instance using
 * {@link org.springframework.security.crypto.factory.PasswordEncoderFactories}.
 * Alternatively, you may create your own custom instance. For example:
 *
 * <pre>
 * String idForEncode = "bcrypt";
 * Map&lt;String,PasswordEncoder&gt; encoders = new HashMap&lt;&gt;();
 * encoders.put(idForEncode, new BCryptPasswordEncoder());
 * encoders.put("noop", NoOpPasswordEncoder.getInstance());
 * encoders.put("pbkdf2", new Pbkdf2PasswordEncoder());
 * encoders.put("scrypt", new SCryptPasswordEncoder());
 * encoders.put("sha256", new StandardPasswordEncoder());
 *
 * PasswordEncoder passwordEncoder = new DelegatingPasswordEncoder(idForEncode, encoders);
 * </pre>
 *
 *
 * <h2>Password Storage Format</h2>
 *
 * The general format for a password is:
 *
 * <pre>
 * {id}encodedPassword
 * </pre>
 *
 * Such that "id" is an identifier used to look up which {@link PasswordEncoder} should be
 * used and "encodedPassword" is the original encoded password for the selected
 * {@link PasswordEncoder}. The "id" must be at the beginning of the password, start with
 * "{" (id prefix) and end with "}" (id suffix). Both id prefix and id suffix can be
 * customized via {@link #DelegatingPasswordEncoder(String, Map, String, String)}. If the
 * "id" cannot be found, the "id" will be null.
 *
 * For example, the following might be a list of passwords encoded using different "id".
 * All of the original passwords are "password".
 *
 * <pre>
 * {bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG
 * {noop}password
 * {pbkdf2}5d923b44a6d129f3ddf3e3c8d29412723dcbde72445e8ef6bf3b508fbf17fa4ed4d6b99ca763d8dc
 * {scrypt}$e0801$8bWJaSu2IKSn9Z9kM+TPXfOc/9bdYSrN1oD9qfVThWEwdRTnO7re7Ei+fUZRJ68k9lTyuTeUp4of4g24hHnazw==$OAOec05+bXxvuu/1qZ6NUR+xQYvYv7BeL1QxwRpY5Pc=
 * {sha256}97cde38028ad898ebc02e690819fa220e88c62e0699403e94fff291cfffaf8410849f27605abcbc0
 * </pre>
 *
 * For the DelegatingPasswordEncoder that we constructed above:
 *
 * <ol>
 * <li>The first password would have a {@code PasswordEncoder} id of "bcrypt" and
 * encodedPassword of "$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG". When
 * matching it would delegate to
 * {@link org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder}</li>
 * <li>The second password would have a {@code PasswordEncoder} id of "noop" and
 * encodedPassword of "password". When matching it would delegate to
 * {@link NoOpPasswordEncoder}</li>
 * <li>The third password would have a {@code PasswordEncoder} id of "pbkdf2" and
 * encodedPassword of
 * "5d923b44a6d129f3ddf3e3c8d29412723dcbde72445e8ef6bf3b508fbf17fa4ed4d6b99ca763d8dc".
 * When matching it would delegate to {@link Pbkdf2PasswordEncoder}</li>
 * <li>The fourth password would have a {@code PasswordEncoder} id of "scrypt" and
 * encodedPassword of
 * "$e0801$8bWJaSu2IKSn9Z9kM+TPXfOc/9bdYSrN1oD9qfVThWEwdRTnO7re7Ei+fUZRJ68k9lTyuTeUp4of4g24hHnazw==$OAOec05+bXxvuu/1qZ6NUR+xQYvYv7BeL1QxwRpY5Pc="
 * When matching it would delegate to
 * {@link org.springframework.security.crypto.scrypt.SCryptPasswordEncoder}</li>
 * <li>The final password would have a {@code PasswordEncoder} id of "sha256" and
 * encodedPassword of
 * "97cde38028ad898ebc02e690819fa220e88c62e0699403e94fff291cfffaf8410849f27605abcbc0".
 * When matching it would delegate to {@link StandardPasswordEncoder}</li>
 * </ol>
 *
 * <h2>Password Encoding</h2>
 *
 * The {@code idForEncode} passed into the constructor determines which
 * {@link PasswordEncoder} will be used for encoding passwords. In the
 * {@code DelegatingPasswordEncoder} we constructed above, that means that the result of
 * encoding "password" would be delegated to {@code BCryptPasswordEncoder} and be prefixed
 * with "{bcrypt}". The end result would look like:
 *
 * <pre>
 * {bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG
 * </pre>
 *
 * <h2>Password Matching</h2>
 *
 * Matching is done based upon the "id" and the mapping of the "id" to the
 * {@link PasswordEncoder} provided in the constructor. Our example in "Password Storage
 * Format" provides a working example of how this is done.
 *
 * By default the result of invoking {@link #matches(CharSequence, String)} with a
 * password with an "id" that is not mapped (including a null id) will result in an
 * {@link IllegalArgumentException}. This behavior can be customized using
 * {@link #setDefaultPasswordEncoderForMatches(PasswordEncoder)}.
 *
 * @author Rob Winch
 * @author Michael Simons
 * @author heowc
 * @author Jihoon Cha
 * @since 5.0
 * @see org.springframework.security.crypto.factory.PasswordEncoderFactories
 */
public class DelegatingPasswordEncoder implements PasswordEncoder {

	private static final String DEFAULT_ID_PREFIX = "{";

	private static final String DEFAULT_ID_SUFFIX = "}";

	private static final String NO_PASSWORD_ENCODER_MAPPED = "There is no password encoder mapped for the id '%s'. "
			+ "Check your configuration to ensure it matches one of the registered encoders.";

	private static final String NO_PASSWORD_ENCODER_PREFIX = "Given that there is no default password encoder configured, each password must have a password encoding prefix. "
			+ "Please either prefix this password with '{noop}' or set a default password encoder in `DelegatingPasswordEncoder`.";

	private static final String MALFORMED_PASSWORD_ENCODER_PREFIX = "The name of the password encoder is improperly "
			+ "formatted or incomplete. The format should be '%sENCODER%spassword'.";

	private final String idPrefix;

	private final String idSuffix;

	private final String idForEncode;

	private final PasswordEncoder passwordEncoderForEncode;

	private final Map<String, PasswordEncoder> idToPasswordEncoder;

	private PasswordEncoder defaultPasswordEncoderForMatches = new UnmappedIdPasswordEncoder();

	/**
	 * Creates a new instance
	 * @param idForEncode the id used to lookup which {@link PasswordEncoder} should be
	 * used for {@link #encode(CharSequence)}
	 * @param idToPasswordEncoder a Map of id to {@link PasswordEncoder} used to determine
	 * which {@link PasswordEncoder} should be used for
	 * {@link #matches(CharSequence, String)}
	 */
	public DelegatingPasswordEncoder(String idForEncode, Map<String, PasswordEncoder> idToPasswordEncoder) {
		this(idForEncode, idToPasswordEncoder, DEFAULT_ID_PREFIX, DEFAULT_ID_SUFFIX);
	}

	/**
	 * Creates a new instance
	 * @param idForEncode the id used to lookup which {@link PasswordEncoder} should be
	 * used for {@link #encode(CharSequence)}
	 * @param idToPasswordEncoder a Map of id to {@link PasswordEncoder} used to determine
	 * which {@link PasswordEncoder} should be used for
	 * @param idPrefix the prefix that denotes the start of the id in the encoded results
	 * @param idSuffix the suffix that denotes the end of an id in the encoded results
	 * {@link #matches(CharSequence, String)}
	 */
	public DelegatingPasswordEncoder(String idForEncode, Map<String, PasswordEncoder> idToPasswordEncoder,
			String idPrefix, String idSuffix) {
		if (idForEncode == null) {
			throw new IllegalArgumentException("idForEncode cannot be null");
		}
		if (idPrefix == null) {
			throw new IllegalArgumentException("prefix cannot be null");
		}
		if (idSuffix == null || idSuffix.isEmpty()) {
			throw new IllegalArgumentException("suffix cannot be empty");
		}
		if (idPrefix.contains(idSuffix)) {
			throw new IllegalArgumentException("idPrefix " + idPrefix + " cannot contain idSuffix " + idSuffix);
		}

		if (!idToPasswordEncoder.containsKey(idForEncode)) {
			throw new IllegalArgumentException(
					"idForEncode " + idForEncode + "is not found in idToPasswordEncoder " + idToPasswordEncoder);
		}
		for (String id : idToPasswordEncoder.keySet()) {
			if (id == null) {
				continue;
			}
			if (!idPrefix.isEmpty() && id.contains(idPrefix)) {
				throw new IllegalArgumentException("id " + id + " cannot contain " + idPrefix);
			}
			if (id.contains(idSuffix)) {
				throw new IllegalArgumentException("id " + id + " cannot contain " + idSuffix);
			}
		}
		this.idForEncode = idForEncode;
		this.passwordEncoderForEncode = idToPasswordEncoder.get(idForEncode);
		this.idToPasswordEncoder = new HashMap<>(idToPasswordEncoder);
		this.idPrefix = idPrefix;
		this.idSuffix = idSuffix;
	}

	/**
	 * Sets the {@link PasswordEncoder} to delegate to for
	 * {@link #matches(CharSequence, String)} if the id is not mapped to a
	 * {@link PasswordEncoder}.
	 *
	 * <p>
	 * The encodedPassword provided will be the full password passed in including the
	 * {"id"} portion.* For example, if the password of "{notmapped}foobar" was used, the
	 * "id" would be "notmapped" and the encodedPassword passed into the
	 * {@link PasswordEncoder} would be "{notmapped}foobar".
	 * </p>
	 * @param defaultPasswordEncoderForMatches the encoder to use. The default is to throw
	 * an {@link IllegalArgumentException}
	 */
	public void setDefaultPasswordEncoderForMatches(PasswordEncoder defaultPasswordEncoderForMatches) {
		if (defaultPasswordEncoderForMatches == null) {
			throw new IllegalArgumentException("defaultPasswordEncoderForMatches cannot be null");
		}
		this.defaultPasswordEncoderForMatches = defaultPasswordEncoderForMatches;
	}

	@Override
	public String encode(CharSequence rawPassword) {
		return this.idPrefix + this.idForEncode + this.idSuffix + this.passwordEncoderForEncode.encode(rawPassword);
	}

	@Override
	public boolean matches(CharSequence rawPassword, String prefixEncodedPassword) {
		if (rawPassword == null && prefixEncodedPassword == null) {
			return true;
		}
		String id = extractId(prefixEncodedPassword);
		PasswordEncoder delegate = this.idToPasswordEncoder.get(id);
		if (delegate == null) {
			return this.defaultPasswordEncoderForMatches.matches(rawPassword, prefixEncodedPassword);
		}
		String encodedPassword = extractEncodedPassword(prefixEncodedPassword);
		return delegate.matches(rawPassword, encodedPassword);
	}

	private String extractId(String prefixEncodedPassword) {
		if (prefixEncodedPassword == null) {
			return null;
		}
		int start = prefixEncodedPassword.indexOf(this.idPrefix);
		if (start != 0) {
			return null;
		}
		int end = prefixEncodedPassword.indexOf(this.idSuffix, start);
		if (end < 0) {
			return null;
		}
		return prefixEncodedPassword.substring(start + this.idPrefix.length(), end);
	}

	@Override
	public boolean upgradeEncoding(String prefixEncodedPassword) {
		String id = extractId(prefixEncodedPassword);
		if (!this.idForEncode.equalsIgnoreCase(id)) {
			return true;
		}
		else {
			String encodedPassword = extractEncodedPassword(prefixEncodedPassword);
			return this.idToPasswordEncoder.get(id).upgradeEncoding(encodedPassword);
		}
	}

	private String extractEncodedPassword(String prefixEncodedPassword) {
		int start = prefixEncodedPassword.indexOf(this.idSuffix);
		return prefixEncodedPassword.substring(start + this.idSuffix.length());
	}

	/**
	 * Default {@link PasswordEncoder} that throws an exception telling that a suitable
	 * {@link PasswordEncoder} for the id could not be found.
	 */
	private class UnmappedIdPasswordEncoder implements PasswordEncoder {

		@Override
		public String encode(CharSequence rawPassword) {
			throw new UnsupportedOperationException("encode is not supported");
		}

		@Override
		public boolean matches(CharSequence rawPassword, String prefixEncodedPassword) {
			String id = extractId(prefixEncodedPassword);
			if (StringUtils.hasText(id)) {
				throw new IllegalArgumentException(String.format(NO_PASSWORD_ENCODER_MAPPED, id));
			}
			if (StringUtils.hasText(prefixEncodedPassword)) {
				int start = prefixEncodedPassword.indexOf(DelegatingPasswordEncoder.this.idPrefix);
				int end = prefixEncodedPassword.indexOf(DelegatingPasswordEncoder.this.idSuffix, start);
				if (start < 0 && end < 0) {
					throw new IllegalArgumentException(NO_PASSWORD_ENCODER_PREFIX);
				}
			}
			throw new IllegalArgumentException(String.format(MALFORMED_PASSWORD_ENCODER_PREFIX,
					DelegatingPasswordEncoder.this.idPrefix, DelegatingPasswordEncoder.this.idSuffix));
		}

	}

}
