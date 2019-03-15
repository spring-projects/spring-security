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

package sample;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import reactor.test.StepVerifier;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(SpringRunner.class)
@ContextConfiguration(classes = HelloWebfluxMethodApplication.class)
@ActiveProfiles("test")
public class HelloWorldMessageServiceTests {
	@Autowired
	HelloWorldMessageService messages;

	@Test
	public void messagesWhenNotAuthenticatedThenDenied() {
		StepVerifier.create(this.messages.findMessage())
			.expectError(AccessDeniedException.class)
			.verify();
	}

	@Test
	@WithMockUser
	public void messagesWhenUserThenDenied() {
		StepVerifier.create(this.messages.findMessage())
			.expectError(AccessDeniedException.class)
			.verify();
	}

	@Test
	@WithMockUser(roles = "ADMIN")
	public void messagesWhenAdminThenOk() {
		StepVerifier.create(this.messages.findMessage())
			.expectNext("Hello World!")
			.verifyComplete();
	}
}
