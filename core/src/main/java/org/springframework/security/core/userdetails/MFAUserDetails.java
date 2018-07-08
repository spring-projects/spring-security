package org.springframework.security.core.userdetails;

public interface MFAUserDetails extends UserDetails {

	boolean isSingleFactorAuthenticationAllowed();

}
