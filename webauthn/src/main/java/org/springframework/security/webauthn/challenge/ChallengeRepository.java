/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.webauthn.challenge;

import com.webauthn4j.data.client.challenge.Challenge;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * An API to allow changing the method in which the expected {@link Challenge} is
 * associated to the {@link HttpServletRequest}. For example, it may be stored in
 * {@link HttpSession}.
 *
 * @see HttpSessionChallengeRepository
 */
public interface ChallengeRepository {

	/**
	 * Generates a {@link Challenge}
	 *
	 * @return the {@link Challenge} that was generated. Cannot be null.
	 */
	Challenge generateChallenge();

	/**
	 * Saves the {@link Challenge} using the {@link HttpServletRequest} and
	 * {@link HttpServletResponse}. If the {@link Challenge} is null, it is the same as
	 * deleting it.
	 *
	 * @param challenge the {@link Challenge} to save or null to delete
	 * @param request   the {@link HttpServletRequest} to use
	 */
	void saveChallenge(Challenge challenge, HttpServletRequest request);

	/**
	 * Loads the expected {@link Challenge} from the {@link HttpServletRequest}
	 *
	 * @param request the {@link HttpServletRequest} to use
	 * @return the {@link Challenge} or null if none exists
	 */
	Challenge loadChallenge(HttpServletRequest request);

	/**
	 * Loads or generates {@link Challenge} from the {@link HttpServletRequest}
	 *
	 * @param request the {@link HttpServletRequest} to use
	 * @return the {@link Challenge} or null if none exists
	 */
	default Challenge loadOrGenerateChallenge(HttpServletRequest request) {
		Challenge challenge = this.loadChallenge(request);
		if (challenge == null) {
			challenge = this.generateChallenge();
			this.saveChallenge(challenge, request);
		}
		return challenge;
	}

}

