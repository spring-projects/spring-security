
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<#import "spring.ftl" as spring />

<html>
  <head>
    <title>Acegi Security Web.xml Converter</title>
  </head>
  <body>
     <form method="POST">
         <@spring.bind "command.webXml" />
         <textarea name="webXml" rows="40" cols="80">${spring.status.value?default("Paste your web.xml here.")}</textarea>
         <br />
         <@spring.showErrors "<br />"/>
         <input type="submit" value="Convert"/>
     </form>

  </body>
</html>