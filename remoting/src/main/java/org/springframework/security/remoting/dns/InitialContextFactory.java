/*
 * Copyright 2009-2016 the original author or authors.
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

package org.springframework.security.remoting.dns;

import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

/**
 * This is used in JndiDnsResolver to get an InitialDirContext for DNS queries.
 *
 * @author Mike Wiesner
 * @since 3.0
 * @see InitialDirContext
 * @see DirContext
 * @see JndiDnsResolver
 */
public interface InitialContextFactory {

	/**
	 * Must return a DirContext which can be used for DNS queries
	 * @return JNDI DirContext
	 */
	DirContext getCtx();

}
