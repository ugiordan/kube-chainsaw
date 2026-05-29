FROM scratch
COPY kube-chainsaw /kube-chainsaw
ENTRYPOINT ["/kube-chainsaw"]
