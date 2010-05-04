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

    @Input
    Login login
    
    TarUpload() {
        compression = Compression.BZIP2
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
