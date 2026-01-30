FROM gcr.io/distroless/static-debian12:nonroot

COPY baton-aws /baton-aws

ENTRYPOINT ["/baton-aws"]
