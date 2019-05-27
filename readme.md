Example Go gRPC + HTTP server for use on GKE. Used in [Medium blog post](https://medium.com/mintensive/go-grpc-server-with-mutual-tls-on-gke-9645389a2224.)

build Docker image:
`docker build -t grpc_gke_example . && docker tag grpc_gke_example eu.gcr.io/<GCP-PROJECT>/grpc_gke_example:1.0.0`

push Docker image into Google container registry:
`docker push eu.gcr.io/<GCP-PROJECT>/grpc_gke_example:1.0.0`   
