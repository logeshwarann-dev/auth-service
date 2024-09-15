FROM golang:1.23.1
WORKDIR /app
COPY . .
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest \
    && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

RUN go mod tidy && go build -o auth-service
CMD ["./auth-service"]
