/*
 * Copyright 2019-2022 the original author or authors.
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

package org.springframework.security.convention.versions;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.util.Arrays;
import java.util.Scanner;

class CommandLineUtils {
	static void runCommand(File dir, String... args) {
		try {
			Process process = new ProcessBuilder()
					.directory(dir)
					.command(args)
					.start();
			writeLinesTo(process.getInputStream(), System.out);
			writeLinesTo(process.getErrorStream(), System.out);
			if (process.waitFor() != 0) {
				new RuntimeException("Failed to run " + Arrays.toString(args));
			}
		} catch (IOException | InterruptedException e) {
			throw new RuntimeException("Failed to run " + Arrays.toString(args), e);
		}
	}

	private static void writeLinesTo(InputStream input, PrintStream out) {
		Scanner scanner = new Scanner(input);
		while(scanner.hasNextLine()) {
			out.println(scanner.nextLine());
		}
	}
}
