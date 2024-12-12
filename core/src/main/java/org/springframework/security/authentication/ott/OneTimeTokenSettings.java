/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.authentication.ott;

import java.time.Duration;

/**
 * A facility for {@link OneTimeToken} configuration settings.
 *
 * @author Micah Moore (Zetetic LLC)
 * @since 6.4.2
 */
public final class OneTimeTokenSettings {

	private static final Duration DEFAULT_TIME_TO_LIVE = Duration.ofMinutes(5L);

	private final Duration timeToLive;

	private OneTimeTokenSettings(Duration timeToLive) {
		this.timeToLive = timeToLive;
	}

	public Duration getTimeToLive() {
		return this.timeToLive;
	}

	public static Builder withDefaults() {
		return new Builder(DEFAULT_TIME_TO_LIVE);
	}

	public static final class Builder {

		private Duration timeToLive;

		Builder(Duration timeToLive) {
			this.timeToLive = timeToLive;
		}

		public Builder timeToLive(Duration timeToLive) {
			this.timeToLive = timeToLive;
			return this;
		}

		public OneTimeTokenSettings build() {
			return new OneTimeTokenSettings(this.timeToLive);
		}

	}

}
