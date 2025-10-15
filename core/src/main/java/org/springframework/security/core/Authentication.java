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

package org.springframework.security.core;

import java.io.Serializable;
import java.security.Principal;
import java.util.Collection;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import org.jspecify.annotations.Nullable;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Represents the token for an authentication request or for an authenticated principal
 * once the request has been processed by the
 * {@link AuthenticationManager#authenticate(Authentication)} method.
 * <p>
 * Once the request has been authenticated, the <tt>Authentication</tt> will usually be
 * stored in a thread-local <tt>SecurityContext</tt> managed by the
 * {@link SecurityContextHolder} by the authentication mechanism which is being used. An
 * explicit authentication can be achieved, without using one of Spring Security's
 * authentication mechanisms, by creating an <tt>Authentication</tt> instance and using
 * the code:
 *
 * <pre>
 * SecurityContext context = SecurityContextHolder.createEmptyContext();
 * context.setAuthentication(anAuthentication);
 * SecurityContextHolder.setContext(context);
 * </pre>
 *
 * Note that unless the <tt>Authentication</tt> has the <tt>authenticated</tt> property
 * set to <tt>true</tt>, it will still be authenticated by any security interceptor (for
 * method or web invocations) which encounters it.
 * <p>
 * In most cases, the framework transparently takes care of managing the security context
 * and authentication objects for you.
 *
 * @author Ben Alex
 */
public interface Authentication extends Principal, Serializable {

	/**
	 * Set by an <code>AuthenticationManager</code> to indicate the authorities that the
	 * principal has been granted. Note that classes should not rely on this value as
	 * being valid unless it has been set by a trusted <code>AuthenticationManager</code>.
	 * <p>
	 * Implementations should ensure that modifications to the returned collection array
	 * do not affect the state of the Authentication object, or use an unmodifiable
	 * instance.
	 * </p>
	 * @return the authorities granted to the principal, or an empty collection if the
	 * token has not been authenticated. Never null.
	 */
	Collection<? extends GrantedAuthority> getAuthorities();

	/**
	 * The credentials that prove the principal is correct. This is usually a password,
	 * but could be anything relevant to the <code>AuthenticationManager</code>. Callers
	 * are expected to populate the credentials.
	 * @return the credentials that prove the identity of the <code>Principal</code>
	 */
	@Nullable Object getCredentials();

	/**
	 * Stores additional details about the authentication request. These might be an IP
	 * address, certificate serial number etc.
	 * @return additional details about the authentication request, or <code>null</code>
	 * if not used
	 */
	@Nullable Object getDetails();

	/**
	 * The identity of the principal being authenticated. In the case of an authentication
	 * request with username and password, this would be the username. Callers are
	 * expected to populate the principal for an authentication request.
	 * <p>
	 * The <tt>AuthenticationManager</tt> implementation will often return an
	 * <tt>Authentication</tt> containing richer information as the principal for use by
	 * the application. Many of the authentication providers will create a
	 * {@code UserDetails} object as the principal.
	 * @return the <code>Principal</code> being authenticated or the authenticated
	 * principal after authentication.
	 */
	@Nullable Object getPrincipal();

	/**
	 * Used to indicate to {@code AbstractSecurityInterceptor} whether it should present
	 * the authentication token to the <code>AuthenticationManager</code>. Typically an
	 * <code>AuthenticationManager</code> (or, more often, one of its
	 * <code>AuthenticationProvider</code>s) will return an immutable authentication token
	 * after successful authentication, in which case that token can safely return
	 * <code>true</code> to this method. Returning <code>true</code> will improve
	 * performance, as calling the <code>AuthenticationManager</code> for every request
	 * will no longer be necessary.
	 * <p>
	 * For security reasons, implementations of this interface should be very careful
	 * about returning <code>true</code> from this method unless they are either
	 * immutable, or have some way of ensuring the properties have not been changed since
	 * original creation.
	 * @return true if the token has been authenticated and the
	 * <code>AbstractSecurityInterceptor</code> does not need to present the token to the
	 * <code>AuthenticationManager</code> again for re-authentication.
	 */
	boolean isAuthenticated();

	/**
	 * See {@link #isAuthenticated()} for a full description.
	 * <p>
	 * Implementations should <b>always</b> allow this method to be called with a
	 * <code>false</code> parameter, as this is used by various classes to specify the
	 * authentication token should not be trusted. If an implementation wishes to reject
	 * an invocation with a <code>true</code> parameter (which would indicate the
	 * authentication token is trusted - a potential security risk) the implementation
	 * should throw an {@link IllegalArgumentException}.
	 * @param isAuthenticated <code>true</code> if the token should be trusted (which may
	 * result in an exception) or <code>false</code> if the token should not be trusted
	 * @throws IllegalArgumentException if an attempt to make the authentication token
	 * trusted (by passing <code>true</code> as the argument) is rejected due to the
	 * implementation being immutable or implementing its own alternative approach to
	 * {@link #isAuthenticated()}
	 */
	void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException;

	/**
	 * A builder based on a given {@link BuildableAuthentication} instance
	 *
	 * @author Josh Cummings
	 * @since 7.0
	 */
	interface Builder<B extends Builder<B>> {

		/**
		 * Apply this authentication instance
		 * <p>
		 * By default, merges the authorities in the provided {@code authentication} with
		 * the authentication being built. Only those authorities that haven't already
		 * been specified to the builder will be added.
		 * </p>
		 * @param authentication the {@link Authentication} to appluy
		 * @return the {@link Builder} for additional configuration
		 * @see BuildableAuthentication#getAuthorities
		 */
		default B authentication(Authentication authentication) {
			return authorities((a) -> {
				Set<String> newAuthorities = a.stream()
					.map(GrantedAuthority::getAuthority)
					.collect(Collectors.toUnmodifiableSet());
				for (GrantedAuthority currentAuthority : authentication.getAuthorities()) {
					if (!newAuthorities.contains(currentAuthority.getAuthority())) {
						a.add(currentAuthority);
					}
				}
			});
		}

		/**
		 * Mutate the authorities with this {@link Consumer}.
		 * <p>
		 * Note that since a non-empty set of authorities implies an
		 * {@link Authentication} is authenticated, this method also marks the
		 * authentication as {@link #authenticated} by default.
		 * </p>
		 * @param authorities a consumer that receives the full set of authorities
		 * @return the {@link Builder} for additional configuration
		 * @see Authentication#getAuthorities
		 */
		B authorities(Consumer<Collection<GrantedAuthority>> authorities);

		/**
		 * Use this credential.
		 * <p>
		 * Note that since some credentials are insecure to store, this method is
		 * implemented as unsupported by default. Only implement or use this method if you
		 * support secure storage of the credential or if your implementation also
		 * implements {@link CredentialsContainer} and the credentials are thereby erased.
		 * </p>
		 * @param credentials the credentials to use
		 * @return the {@link Builder} for additional configuration
		 * @see Authentication#getCredentials
		 */
		default B credentials(@Nullable Object credentials) {
			throw new UnsupportedOperationException(
					String.format("%s does not store credentials", this.getClass().getSimpleName()));
		}

		/**
		 * Use this details object.
		 * <p>
		 * Implementations may choose to use these {@code details} in combination with any
		 * principal from the pre-existing {@link Authentication} instance.
		 * </p>
		 * @param details the details to use
		 * @return the {@link Builder} for additional configuration
		 * @see Authentication#getDetails
		 */
		B details(@Nullable Object details);

		/**
		 * Use this principal.
		 * <p>
		 * Note that in many cases, the principal is strongly-typed. Implementations may
		 * choose to do a type check and are not necessarily expected to allow any object
		 * as a principal.
		 * </p>
		 * <p>
		 * Implementations may choose to use this {@code principal} in combination with
		 * any principal from the pre-existing {@link Authentication} instance.
		 * </p>
		 * @param principal the principal to use
		 * @return the {@link Builder} for additional configuration
		 * @see Authentication#getPrincipal
		 */
		B principal(@Nullable Object principal);

		/**
		 * Mark this authentication as authenticated or not
		 * @param authenticated whether this is an authenticated {@link Authentication}
		 * instance
		 * @return the {@link Builder} for additional configuration
		 * @see Authentication#isAuthenticated
		 */
		B authenticated(boolean authenticated);

		/**
		 * Build an {@link Authentication} instance
		 * @return the {@link Authentication} instance
		 */
		Authentication build();

	}

}
