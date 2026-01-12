import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.tasks.compile.JavaCompile
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

class CompileWarningsErrorPlugin implements Plugin<Project> {
    void apply(Project project) {
        project.tasks.withType(JavaCompile) {
            options.compilerArgs += "-Werror"
        }
        project.tasks.withType(KotlinCompile) {
            kotlinOptions.allWarningsAsErrors = true
        }
    }
}