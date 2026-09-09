pipeline {
  agent any

  options {
    timestamps()
    timeout(time: 30, unit: 'MINUTES')
    buildDiscarder(logRotator(numToKeepStr: '10'))
  }

  environment {
    IMAGE = 'webgoat'
    TAG   = "secure-${BUILD_NUMBER}"
  }

  stages {
    stage('Provenance') {
      steps {
        sh 'git log -1 --oneline'
      }
    }

    stage('Build image') {
      steps {
        sh 'docker build -f Dockerfile.secure -t $IMAGE:$TAG -t $IMAGE:secure .'
      }
    }

    stage('Gate: non-root runtime') {
      steps {
        sh '''
          RUNTIME_UID=$(docker run --rm --entrypoint id $IMAGE:$TAG -u)
          echo "Runtime UID: $RUNTIME_UID"
          if [ "$RUNTIME_UID" = "0" ]; then
            echo "FAIL: image runs as root"
            exit 1
          fi
          echo "PASS: non-root"
        '''
      }
    }
  }

  post {
    always {
      sh 'docker image prune -f || true'
    }
  }
}
