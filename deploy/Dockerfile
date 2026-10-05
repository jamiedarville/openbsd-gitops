# The deployer: watches the Git repository and ships changes to the firewall.
# It holds only tools. The playbook and rules come from the repository it
# clones, so changing how deployment works is also just a commit.
FROM python:3.12-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends git openssh-client libnss-wrapper \
  && rm -rf /var/lib/apt/lists/* \
  && pip install --no-cache-dir ansible-core==2.17.5

# Installed where any user ID the container runs as can read them.
COPY requirements.yml /tmp/requirements.yml
RUN ansible-galaxy collection install -r /tmp/requirements.yml -p /usr/share/ansible/collections \
  && rm -rf /tmp/requirements.yml /root/.ansible

COPY entrypoint.sh /usr/local/bin/fw-deployer
RUN chmod 755 /usr/local/bin/fw-deployer && mkdir /state && chmod 1777 /state

ENV HOME=/state STATE_DIR=/state
VOLUME /state
CMD ["fw-deployer"]
