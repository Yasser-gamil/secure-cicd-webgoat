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

    stage('Export image for scanning') {
      steps {
        sh 'docker save $IMAGE:$TAG -o image.tar'
      }
    }

    stage('SCA + image scan') {
      steps {
        sh '''
          docker run --rm \
            -v "$WORKSPACE":/work \
            -v trivy-cache:/root/.cache/trivy \
            aquasec/trivy image \
              --input /work/image.tar \
              --scanners vuln \
              --format template --template "@contrib/html.tpl" \
              --output /work/trivy-report.html \
              --exit-code 0

          docker run --rm -v "$WORKSPACE":/work alpine \
            chown -R "$(id -u):$(id -g)" /work
        '''
      }
    }

    stage('Gate: base image CRITICALs') {
      steps {
        sh '''
          docker run --rm \
            -v trivy-cache:/root/.cache/trivy \
            -v "$WORKSPACE":/work \
            aquasec/trivy image \
              --input /work/image.tar \
              --scanners vuln \
              --pkg-types os \
              --severity CRITICAL \
              --ignore-unfixed \
              --exit-code 1
        '''
      }
    }
  }

  post {
    always {
      archiveArtifacts artifacts: 'trivy-report.html', allowEmptyArchive: true
      publishHTML(target: [
        reportDir: '.', reportFiles: 'trivy-report.html',
        reportName: 'Trivy Scan', keepAll: true,
        alwaysLinkToLastBuild: true, allowMissing: true
      ])
      sh 'rm -f image.tar || true'
      sh 'docker rmi $IMAGE:$TAG || true'
    }
  }
}
