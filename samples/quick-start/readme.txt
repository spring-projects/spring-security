===============================================================================
                             QUICK-START SAMPLE
===============================================================================

Acegi Security's flexibility can be a bit daunting. Because projects only have
so much budget, and people only have so much time, often the complexity of
getting started can seem too high a price to pay. The quick-start sample is
designed to provide you the basic building blocks needed to be added to your
existing application.

Quick-start is not executable or deployable. It's just a convenient, simple
place where you can see what needs to be added to your web application's
existing files and directories.

What you _will_ need to change in the quick-start configuration:

- It protects a /secure directory from HTTP requests. The /secure directory
  is included (along with a debug.jsp you might find useful), but can be
  deleted as soon as you are up and running. You'll need to setup your own
  URLs to protect in the applicationContext.xml. Search for the 
  FilterInvocationInterceptor bean.

What you _may_ need to change in the quick-start configuration:

- It uses an in-memory list of users as your authentication repository. This
  means you edit the XML file to add users, change their roles etc. If you'd
  prefer to use a database, remove the InMemoryDaoImpl from the 
  applicationContext.xml, and add in a JdbcDaoImpl bean. For an example of
  using the JdbcDaoImpl, search the reference guide.

What does this buy you? Not a great deal more than using the Servlet spec
(although we do support regular expressions and Ant paths for URL matching)!
Seriously, you can use the Servlet spec to protect URLs, so why bother?
The quick-start sample provides you the BASE security building blocks for
your application. Whilst there's nothing wrong with using it instead of the
Servlet spec security just for the better path support or avoiding the
multitude of container authentication configurations, most people will use it
because this foundation allows you to simply tweak configuration if you wish
to:

- Protect your business beans (search for MethodSecurityInterceptor in docs)
- Use enterprise-wide single sign on (see CAS section in docs)
- Use custom authorization voters (see Authorization section in docs)
- Deploy custom authentication providers (see Authentication section in docs)
- Perform BASIC authentication (search for BasicProcessingFilter in docs)
- Automate HTTPS redirection (see Channel Security section in docs)

Good luck! Don't forget we're happy to help. See the end of the docs for
contact details.

$Id$
