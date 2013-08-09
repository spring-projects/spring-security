<?xml version="1.0" encoding="UTF-8" ?>
<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page"
    xmlns:c="http://java.sun.com/jsp/jstl/core"
    xmlns:fn="http://java.sun.com/jsp/jstl/functions"
    xmlns:decorator="http://www.opensymphony.com/sitemesh/decorator"
    xmlns:page="http://www.opensymphony.com/sitemesh/page"
    xmlns:form="http://www.springframework.org/tags/form"
    xmlns:spring="http://www.springframework.org/tags"
    xmlns:sec="http://www.springframework.org/security/tags"
    xmlns:tags="urn:jsptagdir:/WEB-INF/tags" version="2.0">

  <jsp:directive.page contentType="text/html" pageEncoding="UTF-8" />
  <jsp:output omit-xml-declaration="true" />
  <jsp:output doctype-root-element="HTML"
              doctype-system="about:legacy-compat" />
<html lang="en">
  <head>
    <title>SecureMail: <decorator:title/></title>
    <c:url var="faviconUrl" value="/resources/img/favicon.ico"/>
    <link rel="icon" type="image/x-icon" href="${faviconUrl}"/>
    <c:url var="bootstrapUrl" value="/resources/css/bootstrap.css"/>
    <link href="${bootstrapUrl}" rel="stylesheet"></link>
    <style type="text/css">
      /* Sticky footer styles
      -------------------------------------------------- */

      html,
      body {
        height: 100%;
        /* The html and body elements cannot have any padding or margin. */
      }

      /* Wrapper for page content to push down footer */
      #wrap {
        min-height: 100%;
        height: auto !important;
        height: 100%;
        /* Negative indent footer by it's height */
        margin: 0 auto -60px;
      }

      /* Set the fixed height of the footer here */
      #push,
      #footer {
        height: 60px;
      }
      #footer {
        background-color: #f5f5f5;
      }

      /* Lastly, apply responsive CSS fixes as necessary */
      @media (max-width: 767px) {
        #footer {
          margin-left: -20px;
          margin-right: -20px;
          padding-left: 20px;
          padding-right: 20px;
        }
      }



      /* Custom page CSS
      -------------------------------------------------- */
      /* Not required for template or sticky footer method. */

      .container {
        width: auto;
        max-width: 680px;
      }
      .container .credit {
        margin: 20px 0;
        text-align: center;
      }
      a {
          color: green;
      }
      .navbar-text a {
        margin-left: 1em;
      }
    </style>
    <c:url var="bootstrapResponsiveUrl" value="/resources/css/bootstrap-responsive.css"/>
    <link href="${bootstrapResponsiveUrl}" rel="stylesheet"></link>

    <!-- HTML5 shim, for IE6-8 support of HTML5 elements -->
    <!--[if lt IE 9]>
      <script src="http://html5shim.googlecode.com/svn/trunk/html5.js"></script>
    <![endif]-->
  </head>


  <body>
    <div id="wrap">
      <div class="navbar navbar-inverse navbar-static-top">
        <div class="navbar-inner">
          <div class="container">
            <a class="btn btn-navbar" data-toggle="collapse" data-target=".nav-collapse">
              <span class="icon-bar"></span>
              <span class="icon-bar"></span>
              <span class="icon-bar"></span>
            </a>
            <c:url var="homeUrl" value="/"/>
            <c:url var="logoUrl" value="/resources/img/logo.png"/>
            <a class="brand" href="${homeUrl}"><img src="${logoUrl}" alt="Spring Security Sample"/></a>
            <div class="nav-collapse collapse">
              <p class="navbar-text pull-right">
                <c:out value="${pageContext.request.remoteUser}"/>
                <c:url var="logoutUrl" value="/logout"/>
                <a href="${logoutUrl}">Log out</a>
              </p>
              <ul class="nav">
                <c:url var="inboxUrl" value="/"/>
                <li><a href="${inboxUrl}">Inbox</a></li>
                <c:url var="composeUrl" value="/?form"/>
                <li><a href="${composeUrl}">Compose</a></li>
              </ul>
            </div>
          </div>
      </div>
    </div>
      <!-- Begin page content -->
      <div class="container">
        <decorator:body/>
      </div>

      <div id="push"><!--  --></div>
    </div>

    <div id="footer">
      <div class="container">
        <p class="muted credit">Visit the <a href="#">Spring Security</a> site for more <a href="#">samples</a>.</p>
      </div>
    </div>
  </body>
</html>
</jsp:root>