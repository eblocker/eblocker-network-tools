pipeline {
    agent any
    stages {
        stage('Build for Debian Jessie / ARM') {
            steps {
                sh "sudo docker run --rm -t -e BRANCH=${env.BRANCH_NAME} network-tools-arm:jessie"
            }
        }
        stage('Build for Debian Stretch / ARM') {
            steps {
                sh "sudo docker run --rm -t -e BRANCH=${env.BRANCH_NAME} network-tools-arm:stretch"
            }
        }
        stage('Build for Debian Stretch / AMD64') {
            steps {
                sh "sudo docker run --rm -t -e BRANCH=${env.BRANCH_NAME} network-tools-amd64:stretch"
            }
        }
    }
}
