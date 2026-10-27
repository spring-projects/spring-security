---
title: "{{title}}"
category: Releases
publishedAt: {{publishedAt}}
author: {{author}}
---

On behalf of the team and everyone who has contributed, I'm happy to announce that \`{{projectName}} {{version}}\` is available now from Maven Central.
{{#hasCves}}

This release fixes the following {{#multipleCves}}CVEs{{/multipleCves}}{{^multipleCves}}CVE{{/multipleCves}}:

{{#cves}}
* [{{id}}]({{url}})
{{/cves}}
{{/hasCves}}

Make sure to checkout the [What's New](https://docs.spring.io/spring-security/reference/{{version}}/whats-new.html) section of the documentation.

* [Release Notes]({{releaseNotesUrl}})
* [Milestone]({{milestoneUrl}})

Thanks to all who contributed with issue reports and pull requests.

As always, we welcome your feedback on [GitHub]({{githubUrl}}/issues).

[Project Page]({{projectPageUrl}}) | [GitHub]({{githubUrl}}) | [Issues]({{githubUrl}}/issues) | [Documentation]({{docsUrl}})
