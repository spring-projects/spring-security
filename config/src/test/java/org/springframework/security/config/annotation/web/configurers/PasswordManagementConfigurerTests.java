/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers;

import java.net.URI;
import java.util.UUID;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.password.PasswordAction;
import org.springframework.security.authentication.password.PasswordAdvice;
import org.springframework.security.authentication.password.UpdatePasswordAdvisor;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.CompromisedPasswordAdvisor;
import org.springframework.security.web.authentication.password.HttpSessionPasswordAdviceRepository;
import org.springframework.security.web.authentication.password.PasswordAdviceRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link PasswordManagementConfigurer}.
 *
 * @author Evgeniy Cheban
 */
@ExtendWith(SpringTestContextExtension.class)
public class PasswordManagementConfigurerTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	@Test
	public void whenChangePasswordPageNotSetThenDefaultChangePasswordPageUsed() throws Exception {
		this.spring.register(PasswordManagementWithDefaultChangePasswordPageConfig.class).autowire();

		this.mvc.perform(get("/.well-known/change-password"))
			.andExpect(status().isFound())
			.andExpect(redirectedUrl("/change-password"));
	}

	@Test
	public void whenChangePasswordPageSetThenSpecifiedChangePasswordPageUsed() throws Exception {
		this.spring.register(PasswordManagementWithCustomChangePasswordPageConfig.class).autowire();

		this.mvc.perform(get("/.well-known/change-password"))
			.andExpect(status().isFound())
			.andExpect(redirectedUrl("/custom-change-password-page"));
	}

	@Test
	public void whenSettingNullChangePasswordPage() {
		PasswordManagementConfigurer configurer = new PasswordManagementConfigurer();
		assertThatIllegalArgumentException().isThrownBy(() -> configurer.changePasswordPage(null))
			.withMessage("changePasswordPage cannot be empty");
	}

	@Test
	public void whenSettingEmptyChangePasswordPage() {
		PasswordManagementConfigurer configurer = new PasswordManagementConfigurer();
		assertThatIllegalArgumentException().isThrownBy(() -> configurer.changePasswordPage(""))
			.withMessage("changePasswordPage cannot be empty");
	}

	@Test
	public void whenSettingBlankChangePasswordPage() {
		PasswordManagementConfigurer configurer = new PasswordManagementConfigurer();
		assertThatIllegalArgumentException().isThrownBy(() -> configurer.changePasswordPage(" "))
			.withMessage("changePasswordPage cannot be empty");
	}

	@Test
	void whenAdminSetsExpiredAdviceThenUserLoginRedirectsToResetPassword() throws Exception {
		this.spring.register(PasswordManagementConfig.class, AdminController.class, HomeController.class).autowire();
		UserDetailsService users = this.spring.getContext().getBean(UserDetailsService.class);
		UserDetails admin = users.loadUserByUsername("admin");
		this.mvc.perform(get("/").with(user(admin))).andExpect(status().isOk());
		// change the password to a test value
		String random = UUID.randomUUID().toString();
		this.mvc.perform(post("/change-password").with(csrf()).with(user(admin)).param("password", random))
			.andExpect(status().isOk());
		// admin "expires" their own password
		this.mvc.perform(post("/admin/passwords/expire/admin").with(csrf()).with(user(admin)))
			.andExpect(status().isCreated());
		// .andExpect(jsonPath("$.action").value(ChangePasswordAdvice.Action.MUST_CHANGE.toString()));
		// requests redirect to /change-password
		MvcResult result = this.mvc
			.perform(post("/login").with(csrf()).param("username", "admin").param("password", random))
			.andExpect(status().isFound())
			.andExpect(redirectedUrl("/"))
			.andReturn();
		MockHttpSession session = (MockHttpSession) result.getRequest().getSession();
		this.mvc.perform(get("/").session(session))
			.andExpect(status().isFound())
			.andExpect(redirectedUrl("/change-password"));
		// reset the password to update
		random = UUID.randomUUID().toString();
		this.mvc.perform(post("/change-password").with(csrf()).session(session).param("password", random))
			.andExpect(status().isOk());
		// now we're good
		this.mvc.perform(get("/").session(session)).andExpect(status().isOk());
	}

	@Test
	void whenShouldChangeThenUserLoginAllowed() throws Exception {
		this.spring.register(PasswordManagementConfig.class, AdminController.class, HomeController.class).autowire();
		MvcResult result = this.mvc
			.perform(post("/login").with(csrf()).param("username", "user").param("password", "password"))
			.andExpect(status().isFound())
			.andExpect(redirectedUrl("/"))
			.andReturn();
		MockHttpSession session = (MockHttpSession) result.getRequest().getSession();
		this.mvc.perform(get("/").session(session))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("SHOULD_CHANGE")));
	}

	@Configuration
	@EnableWebSecurity
	static class PasswordManagementWithDefaultChangePasswordPageConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			return http
					.passwordManagement(withDefaults())
					.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class PasswordManagementWithCustomChangePasswordPageConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			return http
					.passwordManagement((passwordManagement) -> passwordManagement
						.changePasswordPage("/custom-change-password-page")
					)
					.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	static class PasswordManagementConfig {

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http, UserDetailsService users) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((authz) -> authz
					.requestMatchers("/admin/**").hasRole("ADMIN")
					.anyRequest().authenticated()
				)
				.formLogin(Customizer.withDefaults())
				.passwordManagement(Customizer.withDefaults());
			// @formatter:on
			return http.build();
		}

		@Bean
		InMemoryUserDetailsManager users() {
			UserDetails shouldChange = User.withUserDetails(PasswordEncodedUser.user())
				.passwordAction(PasswordAction.SHOULD_CHANGE)
				.build();
			UserDetails admin = PasswordEncodedUser.admin();
			return new InMemoryUserDetailsManager(shouldChange, admin);
		}

	}

	@RequestMapping("/admin/passwords")
	@RestController
	static class AdminController {

		private final UserDetailsManager users;

		AdminController(InMemoryUserDetailsManager users) {
			this.users = users;
		}

		@GetMapping("/advice/{username}")
		ResponseEntity<PasswordAction> requireChangePassword(@PathVariable("username") String username) {
			UserDetails user = this.users.loadUserByUsername(username);
			if (user == null) {
				return ResponseEntity.notFound().build();
			}
			return ResponseEntity.ok(user.getPasswordAction());
		}

		@PostMapping("/expire/{username}")
		ResponseEntity<PasswordAction> expirePassword(@PathVariable("username") String username) {
			UserDetails user = this.users.loadUserByUsername(username);
			if (user == null) {
				return ResponseEntity.notFound().build();
			}
			UserDetails mustChange = User.withUserDetails(user).passwordAction(PasswordAction.MUST_CHANGE).build();
			this.users.updateUser(mustChange);
			URI uri = URI.create("/admin/passwords/advice/" + username);
			return ResponseEntity.created(uri).body(PasswordAction.MUST_CHANGE);
		}

	}

	@RestController
	static class HomeController {

		private final InMemoryUserDetailsManager passwords;

		private final UpdatePasswordAdvisor passwordAdvisor = new CompromisedPasswordAdvisor();

		private final PasswordAdviceRepository passwordAdviceRepository = new HttpSessionPasswordAdviceRepository();

		private final PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

		HomeController(InMemoryUserDetailsManager passwords) {
			this.passwords = passwords;
		}

		@GetMapping
		PasswordAdvice index(PasswordAdvice advice) {
			return advice;
		}

		@PostMapping("/change-password")
		ResponseEntity<?> changePassword(@AuthenticationPrincipal UserDetails user,
				@RequestParam("password") String password, HttpServletRequest request, HttpServletResponse response) {
			PasswordAdvice advice = this.passwordAdvisor.advise(user, null, password);
			if (advice.getAction() != PasswordAction.NONE) {
				return ResponseEntity.badRequest().body(advice);
			}
			UserDetails updated = User.withUserDetails(user)
				.passwordEncoder(this.encoder::encode)
				.password(password)
				.passwordAction(PasswordAction.NONE)
				.build();
			this.passwords.updateUser(updated);
			this.passwordAdviceRepository.removePasswordAdvice(request, response);
			return ResponseEntity.ok().build();
		}

	}

}
