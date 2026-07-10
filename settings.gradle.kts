pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        mavenCentral()
    }
}

rootProject.name = "keystead-server"

includeBuild("../keystead") {
    dependencySubstitution {
        substitute(module("top.focess:keystead-core")).using(project(":keystead-core"))
    }
}
