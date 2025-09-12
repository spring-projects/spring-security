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

package org.springframework.security.kerberos.authentication.sun;

import java.security.Principal;
import java.util.HashSet;

import javax.security.auth.Subject;

/**
 * JAAS utility functions.
 *
 * @author Bogdan Mustiata
 */
public final class JaasUtil {

	/**
	 * Copy the principal and the credentials into a new Subject.
	 * @param subject
	 * @return
	 */
	public static Subject copySubject(Subject subject) {
		Subject subjectCopy = new Subject(false, new HashSet<Principal>(subject.getPrincipals()),
				new HashSet<Object>(subject.getPublicCredentials()),
				new HashSet<Object>(subject.getPrivateCredentials()));

		return subjectCopy;
	}

	private JaasUtil() {
	}

}
