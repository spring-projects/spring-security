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
package com.google.springframework.security.web.client;

/**
 * This specifies if the {@link com.google.springframework.security.web.client.SecureRestTemplate} should
 * allow request to the local network only or only towards the internet only ( e.g. to prevent access to cloud VM metadata ).
 */
public enum NetworkMode {
	BLOCK_EXTERNAL,
	BLOCK_INTERNAL
}
