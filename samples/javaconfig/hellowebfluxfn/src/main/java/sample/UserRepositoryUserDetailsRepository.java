/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample;

import java.util.Collection;
import java.util.List;

import org.springframework.security.authentication.UserDetailsRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import reactor.core.publisher.Mono;

/**
 * @author Rob Winch
 * @since 5.0
 */
@Component
public class UserRepositoryUserDetailsRepository implements UserDetailsRepository {
	private final UserRepository users;

	public UserRepositoryUserDetailsRepository(UserRepository users) {
		super();
		this.users = users;
	}

	@Override
	public Mono<UserDetails> findByUsername(String username) {
		return this.users
				.findByUsername(username)
				.map(UserDetailsAdapter::new);
	}

	@SuppressWarnings("serial")
	private static class UserDetailsAdapter extends User implements UserDetails {
		private static List<GrantedAuthority> USER_ROLES = AuthorityUtils.createAuthorityList("ROLE_USER");
		private static List<GrantedAuthority> ADMIN_ROLES = AuthorityUtils.createAuthorityList("ROLE_ADMIN", "ROLE_USER");

		private UserDetailsAdapter(User delegate) {
			super(delegate);
		}

		@Override
		public Collection<? extends GrantedAuthority> getAuthorities() {
			return isAdmin() ? ADMIN_ROLES : USER_ROLES ;
		}

		private boolean isAdmin() {
			return getUsername().contains("admin");
		}

		@Override
		public boolean isAccountNonExpired() {
			return true;
		}

		@Override
		public boolean isAccountNonLocked() {
			return true;
		}

		@Override
		public boolean isCredentialsNonExpired() {
			return true;
		}

		@Override
		public boolean isEnabled() {
			return true;
		}
	}
}
