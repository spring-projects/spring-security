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
package org.springframework.security.context;

import java.util.Random;

import junit.framework.ComparisonFailure;
import junit.framework.TestCase;



import org.springframework.security.providers.UsernamePasswordAuthenticationToken;

/**
 * Multi-threaded tests for SecurityContextHolder
 *
 * @author Ben Alex
 * @Author Luke Taylor
 */
public class SecurityContextHolderMTTests extends TestCase{
	private int errors = 0;

	private static final int NUM_OPS = 25;
	private static final int NUM_THREADS = 25;

	public final void setUp() throws Exception {
		SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
	}

	public void testSynchronizationCustomStrategyLoading() {
		SecurityContextHolder.setStrategyName(InheritableThreadLocalSecurityContextHolderStrategy.class.getName());
		assertThat(new SecurityContextHolder().toString().isTrue()
											.lastIndexOf("SecurityContextHolder[strategy='org.springframework.security.context.InheritableThreadLocalSecurityContextHolderStrategy'") != -1);
		loadStartAndWaitForThreads(true, "Main_", NUM_THREADS, false, true);
		assertThat(errors).as("Thread errors detected; review log output for details").isZero();
	}

	public void testSynchronizationGlobal() throws Exception {
		SecurityContextHolder.clearContext();
		SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_GLOBAL);
		loadStartAndWaitForThreads(true, "Main_", NUM_THREADS, true, false);
		assertThat(errors).as("Thread errors detected; review log output for details").isZero();
	}

	public void testSynchronizationInheritableThreadLocal()
		throws Exception {
		SecurityContextHolder.clearContext();
		SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
		loadStartAndWaitForThreads(true, "Main_", NUM_THREADS, false, true);
		assertThat(errors).as("Thread errors detected; review log output for details").isZero();
	}

	public void testSynchronizationThreadLocal() throws Exception {
		SecurityContextHolder.clearContext();
		SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_THREADLOCAL);
		loadStartAndWaitForThreads(true, "Main_", NUM_THREADS, false, false);
		assertThat(errors).as("Thread errors detected; review log output for details").isZero();
	}

	private void startAndRun(Thread[] threads) {
		// Start them up
		for (int i = 0; i < threads.length; i++) {
			threads[i].start();
		}

		// Wait for them to finish
		while (stillRunning(threads)) {
			try {
				Thread.sleep(250);
			} catch (InterruptedException ignore) {}
		}
	}

	private boolean stillRunning(Thread[] threads) {
		for (int i = 0; i < threads.length; i++) {
			if (threads[i].isAlive()) {
				return true;
			}
		}

		return false;
	}

	private void loadStartAndWaitForThreads(boolean topLevelThread, String prefix, int createThreads,
			boolean expectAllThreadsToUseIdenticalAuthentication, boolean expectChildrenToShareAuthenticationWithParent) {
		Thread[] threads = new Thread[createThreads];
		errors = 0;

		if (topLevelThread) {
			// PARENT (TOP-LEVEL) THREAD CREATION
			if (expectChildrenToShareAuthenticationWithParent) {
				// An InheritableThreadLocal
				for (int i = 0; i < threads.length; i++) {
					if ((i % 2) == 0) {
						// Don't inject auth into current thread; neither current thread or child will have authentication
						threads[i] = makeThread(prefix + "Unauth_Parent_" + i, true, false, false, true, null);
					} else {
						// Inject auth into current thread, but not child; current thread will have auth, child will also have auth
						threads[i] = makeThread(prefix + "Auth_Parent_" + i, true, true, false, true,
								prefix + "Auth_Parent_" + i);
					}
				}
			} else if (expectAllThreadsToUseIdenticalAuthentication) {
				// A global
				SecurityContextHolder.getContext()
									.setAuthentication(new UsernamePasswordAuthenticationToken("GLOBAL_USERNAME",
						"pass"));

				for (int i = 0; i < threads.length; i++) {
					if ((i % 2) == 0) {
						// Don't inject auth into current thread;both current thread and child will have same authentication
						threads[i] = makeThread(prefix + "Unauth_Parent_" + i, true, false, true, true,
								"GLOBAL_USERNAME");
					} else {
						// Inject auth into current thread; current thread will have auth, child will also have auth
						threads[i] = makeThread(prefix + "Auth_Parent_" + i, true, true, true, true, "GLOBAL_USERNAME");
					}
				}
			} else {
				// A standard ThreadLocal
				for (int i = 0; i < threads.length; i++) {
					if ((i % 2) == 0) {
						// Don't inject auth into current thread; neither current thread or child will have authentication
						threads[i] = makeThread(prefix + "Unauth_Parent_" + i, true, false, false, false, null);
					} else {
						// Inject auth into current thread, but not child; current thread will have auth, child will not have auth
						threads[i] = makeThread(prefix + "Auth_Parent_" + i, true, true, false, false,
								prefix + "Auth_Parent_" + i);
					}
				}
			}
		} else {
			// CHILD THREAD CREATION
			if (expectChildrenToShareAuthenticationWithParent || expectAllThreadsToUseIdenticalAuthentication) {
				// The children being created are all expected to have security (ie an InheritableThreadLocal/global AND auth was injected into parent)
				for (int i = 0; i < threads.length; i++) {
					String expectedUsername = prefix;

					if (expectAllThreadsToUseIdenticalAuthentication) {
						expectedUsername = "GLOBAL_USERNAME";
					}

					// Don't inject auth into current thread; the current thread will obtain auth from its parent
					// NB: As topLevelThread = true, no further child threads will be created
					threads[i] = makeThread(prefix + "->child->Inherited_Auth_Child_" + i, false, false,
							expectAllThreadsToUseIdenticalAuthentication, false, expectedUsername);
				}
			} else {
				// The children being created are NOT expected to have security (ie not an InheritableThreadLocal OR auth was not injected into parent)
				for (int i = 0; i < threads.length; i++) {
					// Don't inject auth into current thread; neither current thread or child will have authentication
					// NB: As topLevelThread = true, no further child threads will be created
					threads[i] = makeThread(prefix + "->child->Unauth_Child_" + i, false, false, false, false, null);
				}
			}
		}

		// Start and execute the threads
		startAndRun(threads);
	}

	private Thread makeThread(final String threadIdentifier, final boolean topLevelThread,
		final boolean injectAuthIntoCurrentThread, final boolean expectAllThreadsToUseIdenticalAuthentication,
		final boolean expectChildrenToShareAuthenticationWithParent, final String expectedUsername) {
		final Random rnd = new Random();

		Thread t = new Thread(new Runnable() {
			public void run() {
					if (injectAuthIntoCurrentThread) {
						// Set authentication in this thread
						SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
								expectedUsername, "pass"));

						//System.out.println(threadIdentifier + " - set to " + SecurityContextHolder.getContext().getAuthentication());
					} else {
						//System.out.println(threadIdentifier + " - not set (currently " + SecurityContextHolder.getContext().getAuthentication() + ")");
					}

					// Do some operations in current thread, checking authentication is as expected in the current thread (ie another thread doesn't change it)
					for (int i = 0; i < NUM_OPS; i++) {
						String currentUsername = (SecurityContextHolder.getContext().getAuthentication() == null)
							? null : SecurityContextHolder.getContext().getAuthentication().getName();

						if ((i % 7) == 0) {
							System.out.println(threadIdentifier + " at " + i + " username " + currentUsername);
						}

						try {
							assertEquals("Failed on iteration " + i + "; Authentication was '"
								+ currentUsername + "' but principal was expected to contain username '"
								+ expectedUsername + "'", expectedUsername, currentUsername);
						} catch (ComparisonFailure err) {
							errors++;
							throw err;
						}

						try {
							Thread.sleep(rnd.nextInt(250));
						} catch (InterruptedException ignore) {}
					}

					// Load some children threads, checking the authentication is as expected in the children (ie another thread doesn't change it)
					if (topLevelThread) {
						// Make four children, but we don't want the children to have any more children (so anti-nature, huh?)
						if (injectAuthIntoCurrentThread && expectChildrenToShareAuthenticationWithParent) {
							loadStartAndWaitForThreads(false, threadIdentifier, 4,
								expectAllThreadsToUseIdenticalAuthentication, true);
						} else {
							loadStartAndWaitForThreads(false, threadIdentifier, 4,
								expectAllThreadsToUseIdenticalAuthentication, false);
						}
					}
				}
			}, threadIdentifier);

		return t;
	}
}
