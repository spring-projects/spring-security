/*
 * Copyright 2002-2021 the original author or authors.
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

package s101;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.UncheckedIOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.HtmlAnchor;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.github.mustachejava.DefaultMustacheFactory;
import com.github.mustachejava.Mustache;
import com.github.mustachejava.MustacheFactory;
import org.apache.commons.io.IOUtils;
import org.gradle.api.Project;
import org.gradle.api.logging.Logger;
import org.gradle.api.tasks.SourceSet;
import org.gradle.api.tasks.SourceSetContainer;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

public class S101Configurer {
	private static final Pattern VERSION = Pattern.compile("<local-project .* version=\"(.*?)\"");

	private static final int BUFFER = 1024;
	private static final long TOOBIG = 0x10000000; // ~268M
	private static final int TOOMANY = 200;

	private final MustacheFactory mustache = new DefaultMustacheFactory();
	private final Mustache hspTemplate;
	private final Mustache repositoryTemplate;

	private final Path licenseDirectory;

	private final Project project;
	private final Logger logger;

	public S101Configurer(Project project) {
		this.project = project;
		this.logger = project.getLogger();
		Resource template = new ClassPathResource("s101/project.java.hsp");
		try (InputStream is = template.getInputStream()) {
			this.hspTemplate = this.mustache.compile(new InputStreamReader(is), "project");
		} catch (IOException ex) {
			throw new UncheckedIOException(ex);
		}
		template = new ClassPathResource("s101/repository.xml");
		try (InputStream is = template.getInputStream()) {
			this.repositoryTemplate = this.mustache.compile(new InputStreamReader(is), "repository");
		} catch (IOException ex) {
			throw new UncheckedIOException(ex);
		}
		this.licenseDirectory = new File(System.getProperty("user.home") + "/.Structure101/java").toPath();
	}

	public void license(String licenseId) {
		Path licenseFile = this.licenseDirectory.resolve(".structure101license.properties");
		if (needsLicense(licenseFile, licenseId)) {
			writeLicense(licenseFile, licenseId);
		}
	}

	private boolean needsLicense(Path licenseFile, String licenseId) {
		if (!licenseFile.toFile().exists()) {
			return true;
		}
		try {
			String license = new String(Files.readAllBytes(licenseFile));
			return !license.contains(licenseId);
		} catch (IOException ex) {
			throw new RuntimeException(ex);
		}
	}

	private void writeLicense(Path licenseFile, String licenseId) {
		if (!this.licenseDirectory.toFile().mkdirs()) {
			this.licenseDirectory.forEach((path) -> path.toFile().delete());
		}
		try (PrintWriter pw = new PrintWriter(licenseFile.toFile())) {
			pw.println("licensecode=" + licenseId);
		} catch (IOException ex) {
			throw new RuntimeException(ex);
		}
	}

	public void install(File installationDirectory, File configurationDirectory) {
		deleteDirectory(installationDirectory);
		installBuildTool(installationDirectory, configurationDirectory);
	}

	public void configure(File installationDirectory, File configurationDirectory) {
		deleteDirectory(configurationDirectory);
		String version = computeVersionFromInstallation(installationDirectory);
		configureProject(version, configurationDirectory);
	}

	private String computeVersionFromInstallation(File installationDirectory) {
		File buildJar = new File(installationDirectory, "structure101-java-build.jar");
		try (JarInputStream input = new JarInputStream(new FileInputStream(buildJar))) {
			JarEntry entry;
			while ((entry = input.getNextJarEntry()) != null) {
				if (entry.getName().contains("structure101-build.properties")) {
					Properties properties = new Properties();
					properties.load(input);
					return properties.getProperty("s101-build");
				}
			}
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}
		throw new IllegalStateException("Unable to determine Structure101 version");
	}

	private boolean deleteDirectory(File directoryToBeDeleted) {
		File[] allContents = directoryToBeDeleted.listFiles();
		if (allContents != null) {
			for (File file : allContents) {
				deleteDirectory(file);
			}
		}
		return directoryToBeDeleted.delete();
	}

	private String installBuildTool(File installationDirectory, File configurationDirectory) {
		String source = "https://structure101.com/binaries/v6";
		try (final WebClient webClient = new WebClient()) {
			HtmlPage page = webClient.getPage(source);
			Matcher matcher = null;
			for (HtmlAnchor anchor : page.getAnchors()) {
				Matcher candidate = Pattern.compile("(structure101-build-java-all-)(.*).zip").matcher(anchor.getHrefAttribute());
				if (candidate.find()) {
					matcher = candidate;
				}
			}
			if (matcher == null) {
				return null;
			}
			copyZipToFilesystem(source, installationDirectory, matcher.group(1) + matcher.group(2));
			return matcher.group(2);
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}

	private void copyZipToFilesystem(String source, File destination, String name) {
		try (ZipInputStream in = new ZipInputStream(new URL(source + "/" + name + ".zip").openStream())) {
			ZipEntry entry;
			String build = destination.getName();
			int entries = 0;
			long size = 0;
			while ((entry = in.getNextEntry()) != null) {
				if (entry.getName().equals(name + "/")) {
					destination.mkdirs();
				} else if (entry.getName().startsWith(name)) {
					if (entries++ > TOOMANY) {
						throw new IllegalArgumentException("Zip file has more entries than expected");
					}
					if (size + BUFFER > TOOBIG) {
						throw new IllegalArgumentException("Zip file is larger than expected");
					}
					String filename = entry.getName().replace(name, build);
					if (filename.contains("maven")) {
						continue;
					}
					if (filename.contains("jxbrowser")) {
						continue;
					}
					if (filename.contains("jetty")) {
						continue;
					}
					if (filename.contains("jfreechart")) {
						continue;
					}
					if (filename.contains("piccolo2d")) {
						continue;
					}
					if (filename.contains("plexus")) {
						continue;
					}
					if (filename.contains("websocket")) {
						continue;
					}
					validateFilename(filename, build);
					this.logger.info("Downloading " + filename);
					try (OutputStream out = new FileOutputStream(new File(destination.getParentFile(), filename))) {
						byte[] data = new byte[BUFFER];
						int read;
						while ((read = in.read(data, 0, BUFFER)) != -1 && TOOBIG - size >= read) {
							out.write(data, 0, read);
							size += read;
						}
					}
				}
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private String validateFilename(String filename, String intendedDir)
			throws java.io.IOException {
		File f = new File(filename);
		String canonicalPath = f.getCanonicalPath();

		File iD = new File(intendedDir);
		String canonicalID = iD.getCanonicalPath();

		if (canonicalPath.startsWith(canonicalID)) {
			return canonicalPath;
		} else {
			throw new IllegalArgumentException("File is outside extraction target directory.");
		}
	}

	private void configureProject(String version, File configurationDirectory) {
		configurationDirectory.mkdirs();
		Map<String, Object> model = hspTemplateValues(version, configurationDirectory);
		copyToProject(this.hspTemplate, model, new File(configurationDirectory, "project.java.hsp"));
		copyToProject("s101/config.xml", new File(configurationDirectory, "config.xml"));
		File repository = new File(configurationDirectory, "repository");
		File snapshots = new File(repository, "snapshots");
		if (!snapshots.exists() && !snapshots.mkdirs()) {
			throw new IllegalStateException("Unable to create snapshots directory");
		}
		copyToProject(this.repositoryTemplate, model, new File(repository, "repository.xml"));
	}

	private void copyToProject(String location, File destination) {
		Resource resource = new ClassPathResource(location);
		try (InputStream is = resource.getInputStream();
			OutputStream os = new FileOutputStream(destination)) {
			IOUtils.copy(is, os);
		} catch (IOException ex) {
			throw new UncheckedIOException(ex);
		}
	}

	private void copyToProject(Mustache view, Map<String, Object> model, File destination) {
		try (OutputStream os = new FileOutputStream(destination)) {
			view.execute(new OutputStreamWriter(os), model).flush();
		} catch (IOException ex) {
			throw new UncheckedIOException(ex);
		}
	}

	private Map<String, Object> hspTemplateValues(String version, File configurationDirectory) {
		Map<String, Object> values = new LinkedHashMap<>();
		values.put("version", version);
		values.put("patchVersion", version.split("\\.")[2]);
		values.put("relativeTo", "const(THIS_FILE)/" + configurationDirectory.toPath().relativize(this.project.getProjectDir().toPath()));

		List<Map<String, Object>> entries = new ArrayList<>();
		Set<Project> projects = this.project.getAllprojects();
		for (Project p : projects) {
			SourceSetContainer sourceSets = (SourceSetContainer) p.getExtensions().findByName("sourceSets");
			if (sourceSets == null) {
				continue;
			}
			for (SourceSet source : sourceSets) {
				Set<File> classDirs = source.getOutput().getClassesDirs().getFiles();
				for (File directory : classDirs) {
					Map<String, Object> entry = new HashMap<>();
					entry.put("path", this.project.getProjectDir().toPath().relativize(directory.toPath()));
					entry.put("module", p.getName());
					entries.add(entry);
				}
			}
		}
		values.put("entries", entries);
		return values;
	}
}
