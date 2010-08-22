import org.gradle.api.DefaultTask;
import org.gradle.api.tasks.*;
import org.gradle.api.tasks.bundling.Tar;
import org.gradle.api.tasks.bundling.Compression;

/**
 * Extends the Tar task, uploading the created archive to a remote directory, unpacking and deleting it.
 * Requires Ant ssh (jsch) support.
 */
class TarUpload extends Tar {
    @Input
    String remoteDir
    Login login
    @Input
    String host
    
    TarUpload() {
        compression = Compression.BZIP2
        if (project.configurations.findByName('antjsch') == null) {
            project.configurations.add('antjsch')
            project.dependencies {
                antjsch 'org.apache.ant:ant-jsch:1.8.1'
            }
            def classpath = project.configurations.antjsch.asPath
            project.ant {
                taskdef(name: 'scp', classname: 'org.apache.tools.ant.taskdefs.optional.ssh.Scp', classpath: classpath)
                taskdef(name: 'sshexec', classname: 'org.apache.tools.ant.taskdefs.optional.ssh.SSHExec', classpath: classpath)
            }
        }
    }
    
    @TaskAction
    void copy() {
        super.copy();
        upload();
    }
    
    def upload() {
        String username = login.username
        String password = login.password
        String host = login.host
        project.ant {
            scp(file: archivePath, todir: "$username@$host:$remoteDir", password: password)
            sshexec(host: host, username: username, password: password, command: "cd $remoteDir && tar -xjf $archiveName")
            sshexec(host: host, username: username, password: password, command: "rm $remoteDir/$archiveName")
        }
    }

    void setLogin(Login login) {
        dependsOn(login)
        this.login = login
        this.host = login.host
    }
}

/**
 * Stores login information for a remote host.
 */
class Login extends DefaultTask {
    @Input
    String host
    String username
    String password

    @TaskAction
    login() {
        project.ant {
            input("Please enter the ssh username for host '$host'", addproperty: "user.$host")
            input("Please enter the ssh password '$host'", addproperty: "pass.$host")
        }
        username = ant.properties["user.$host"]
        password = ant.properties["pass.$host"]
    }
}
