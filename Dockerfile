FROM gcr.io/distroless/static-debian11:nonroot
ENTRYPOINT ["/baton-aws"]
COPY baton-aws /