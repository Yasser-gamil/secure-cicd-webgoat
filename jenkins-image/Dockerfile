FROM docker:cli AS dockercli

FROM jenkins/jenkins:lts
USER root
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
COPY plugins.txt /usr/share/jenkins/ref/plugins.txt
USER jenkins
RUN jenkins-plugin-cli --plugin-file /usr/share/jenkins/ref/plugins.txt
