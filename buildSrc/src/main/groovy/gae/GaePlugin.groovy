package gae;

import com.google.appengine.tools.admin.AppCfg
import org.gradle.api.*;

class GaePlugin implements Plugin<Project> {
    public void apply(Project project) {
        if (!project.hasProperty('appEngineSdkRoot')) {
            println "'appEngineSdkRoot' must be set in gradle.properties"
        } else {
            System.setProperty('appengine.sdk.root', project.property('appEngineSdkRoot'))
        }

        File explodedWar = new File(project.buildDir, "gae-exploded")

        project.task('gaeDeploy') << {
            AppCfg.main("update", explodedWar.toString())
        }

        project.gaeDeploy.dependsOn project.war

        project.war.doLast {
          ant.unzip(src: project.war.archivePath, dest: explodedWar)
        }
    }
}
