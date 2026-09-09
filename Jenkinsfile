pipeline {
  agent any

  options {
    timestamps()
    timeout(time: 45, unit: 'MINUTES')
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

    stage('DAST: ZAP baseline') {
      steps {
        sh '''
          docker rm -f webgoat-target 2>/dev/null || true
          docker run -d --name webgoat-target --network zapnet $IMAGE:$TAG

          echo "Waiting for application readiness..."
          READY=0
          for i in $(seq 1 60); do
            if docker run --rm --network zapnet curlimages/curl:latest \
                 -sf http://webgoat-target:8080/WebGoat/actuator/health >/dev/null 2>&1; then
              echo "Application ready (attempt $i)"
              READY=1
              break
            fi
            sleep 2
          done
          if [ "$READY" != "1" ]; then
            echo "FAIL: application never became ready - aborting scan"
            docker logs webgoat-target | tail -30
            exit 1
          fi

          docker run --rm --network zapnet \
            -v "$WORKSPACE":/zap/wrk:rw \
            ghcr.io/zaproxy/zaproxy:stable \
            zap-baseline.py \
              -t http://webgoat-target:8080/WebGoat \
              -r zap-report.html \
              -J zap-report.json \
              -m 2 -I

          docker run --rm -v "$WORKSPACE":/work alpine \
            chown -R "$(id -u):$(id -g)" /work
        '''
      }
    }

    stage('Gate: DAST scan validity') {
      steps {
        sh '''
          if [ ! -s zap-report.json ]; then
            echo "FAIL: no ZAP report produced"
            exit 1
          fi
          ALERTS=$(grep -o '"alert"' zap-report.json | wc -l)
          echo "ZAP alerts reported: $ALERTS"
          if [ "$ALERTS" -lt 1 ]; then
            echo "FAIL: zero findings against a deliberately vulnerable target."
            echo "This indicates the scan did not reach the application."
            exit 1
          fi
          echo "PASS: scan reached the target and produced findings"
        '''
      }
    }
  }

  post {
    always {
      sh 'docker rm -f webgoat-target || true'
      archiveArtifacts artifacts: 'trivy-report.html,zap-report.html,zap-report.json', allowEmptyArchive: true
      publishHTML(target: [
        reportDir: '.', reportFiles: 'trivy-report.html',
        reportName: 'Trivy Scan', keepAll: true,
        alwaysLinkToLastBuild: true, allowMissing: true
      ])
      publishHTML(target: [
        reportDir: '.', reportFiles: 'zap-report.html',
        reportName: 'ZAP DAST', keepAll: true,
        alwaysLinkToLastBuild: true, allowMissing: true
      ])
      sh 'rm -f image.tar || true'
      sh 'docker rmi $IMAGE:$TAG || true'
    }
  }
}
