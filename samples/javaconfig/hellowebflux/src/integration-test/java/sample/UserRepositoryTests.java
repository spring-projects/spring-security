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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 * @author Rob Winch
 * @since 5.0
 */
@SuppressWarnings("unused")
@RunWith(SpringRunner.class)
@ContextConfiguration(classes = HelloWebfluxApplication.class)
@TestPropertySource(properties = "server.port=0")
public class UserRepositoryTests {

	@Autowired UserRepository repository;

	String robUsername = "rob";

	@Test
	public void findByUsernameWhenUsernameMatchesThenFound() {
		assertThat(repository.findByUsername(this.robUsername).block()).isNotNull();
	}

	@Test
	public void findByUsernameWhenUsernameDoesNotMatchThenFound() {
		assertThat(repository.findByUsername(this.robUsername + "NOTFOUND").block()).isNull();
	}
}
