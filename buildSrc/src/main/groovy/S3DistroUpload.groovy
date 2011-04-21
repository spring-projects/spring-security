
import org.gradle.api.DefaultTask
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.TaskAction
import org.jets3t.service.security.AWSCredentials
import org.jets3t.service.impl.rest.httpclient.RestS3Service
import org.jets3t.service.S3Service
import org.jets3t.service.model.S3Bucket
import org.jets3t.service.model.S3Object
import org.jets3t.service.acl.AccessControlList

/**
 * @author Luke Taylor
 */
class S3DistroUpload extends DefaultTask {
    @InputFile
    File archiveFile

    @Input
    String bucketName = 'dist.springframework.org'

    // 'Spring Security'
    @Input
    String projectName = project.description

    // e.g 'SEC'
    @Input
    String projectKey

    @TaskAction
    def upload() {
        def accessKey = project.s3AccessKey
        def secretKey = project.s3SecretAccessKey
        def version = project.version.toString()

        assert version.length() > 0
        assert accessKey.length() > 0
        assert secretKey.length() > 0
        assert projectName.length() > 0

        assert archiveFile.exists()

        String archiveName = archiveFile.getName()

        logger.info("Creating SHA checksum file...")
        project.ant.checksum(file: archiveFile, algorithm: 'SHA1', fileext: '.sha1', forceoverwrite: 'true')
        File shaFile = "${archiveFile}.sha1" as File

        assert shaFile.exists()

        AWSCredentials creds = new AWSCredentials(accessKey, secretKey);
        S3Service s3 = new RestS3Service(creds)
        S3Bucket bucket = new S3Bucket(bucketName)

        String releaseType = releaseType(version)

        String key = releaseType + '/' + projectKey + '/' + archiveName

        S3Object archiveDest = new S3Object(bucket, key)
        archiveDest.setAcl(AccessControlList.REST_CANNED_PUBLIC_READ)
        archiveDest.setDataInputFile(archiveFile)
        archiveDest.setContentLength(archiveFile.length())
        archiveDest.addMetadata('project.name', projectName)
        archiveDest.addMetadata('bundle.version', version)
        archiveDest.addMetadata('release.type', releaseType)
        archiveDest.addMetadata('package.file.name', archiveName)

        logger.info("Uploading archive " + archiveFile.getName() + " to " + archiveDest + "...")
        s3.putObject(bucket, archiveDest)
        logger.info("Done")

        S3Object shaDest = new S3Object(bucket, key + '.sha1')
        shaDest.setAcl(AccessControlList.REST_CANNED_PUBLIC_READ)
        shaDest.setDataInputFile(shaFile)
        shaDest.setContentLength(shaFile.length())

        logger.info("Uploading SHA checksum " + shaFile.getName() + " to " + key + '.sha1' + "...")
        s3.putObject(bucket, shaDest);
        logger.info("Done")
    }

    def releaseType(String version) {
        if (version.endsWith('RELEASE')) {
            'release'
        } else if (version.endsWith('SNAPSHOT')) {
            'snapshot'
        } else {
            'milestone'
        }
    }
}
