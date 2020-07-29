/*
 * Copyright 2002-2017 the original author or authors.
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

package samples.data;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import samples.DataConfig;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DataConfig.class)
public class SecurityMessageRepositoryTests {
	@Autowired
	SecurityMessageRepository repository;

	User user;

	@Before
	public void setup() {
		user = new User();
		user.setId(0L);
		List<GrantedAuthority> authorities = AuthorityUtils
				.createAuthorityList("ROLE_USER");
		UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
				user, "notused", authorities);
		SecurityContextHolder.getContext().setAuthentication(authentication);
	}

	@After
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void findAllOnlyToCurrentUser() {
		Long expectedId = user.getId();
		List<Message> messages = repository.findAll();
		assertThat(messages).hasSize(3);
		for (Message m : messages) {
			assertThat(m.getTo().getId()).isEqualTo(expectedId);
		}
	}
}
