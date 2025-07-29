package org.springframework.security.authentication.password;

public interface ChangePasswordReasons {

	String COMPROMISED = "compromised";

	String EXPIRED = "expired";

	String MISSING_CHARACTERS = "missing_characters";

	String REPEATED = "repeated";

	String TOO_LONG = "too_long";

	String TOO_SHORT = "too_short";

	String UNSUPPORTED_CHARACTERS = "unsupported_characters";
}
