FROM golang:1.23-alpine

WORKDIR /app

COPY ../go.mod ./
COPY ../go.sum ./

COPY ./client ./client
COPY ../merkle ./merkle
COPY ../crypto ./crypto

RUN go build -o client ./client/client.go

CMD ["/app/client/client"]
