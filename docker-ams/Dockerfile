FROM registry.access.redhat.com/ubi9/ubi-minimal:latest
ARG TARGETARCH
RUN microdnf install -y ca-certificates && microdnf clean all
RUN groupadd -r livekit && useradd -r -g livekit livekit
COPY bin/livekit-jwt-service-ams-${TARGETARCH} /usr/local/bin/lk-jwt-service-ams
USER livekit
EXPOSE 8080
CMD ["/usr/local/bin/lk-jwt-service-ams"]
