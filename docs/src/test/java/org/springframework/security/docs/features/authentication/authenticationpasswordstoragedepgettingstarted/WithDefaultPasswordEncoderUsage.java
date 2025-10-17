package org.springframework.security.docs.features.authentication.authenticationpasswordstoragedepgettingstarted;

import java.util.List;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import static org.springframework.security.core.userdetails.User.UserBuilder;

public class WithDefaultPasswordEncoderUsage {
	public UserDetails createSingleUser() {
		// tag::createSingleUser[]
		UserDetails user = User.withDefaultPasswordEncoder()
				.username("user")
				.password("password")
				.roles("user")
				.build();
		System.out.println(user.getPassword());
		// {bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG
		// end::createSingleUser[]
		return user;
	}

	public List<UserDetails> createMultipleUsers() {
		// tag::createMultipleUsers[]
		UserBuilder users = User.withDefaultPasswordEncoder();
		UserDetails user = users
				.username("user")
				.password("password")
				.roles("USER")
				.build();
		UserDetails admin = users
				.username("admin")
				.password("password")
				.roles("USER","ADMIN")
				.build();
		// end::createMultipleUsers[]
		return List.of(user, admin);
	}
}
