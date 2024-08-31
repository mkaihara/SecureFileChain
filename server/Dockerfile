FROM golang:1.23-alpine

WORKDIR /app

COPY ../go.mod ./

COPY ./server ./server
COPY ../merkle ./merkle
COPY ../crypto ./crypto
RUN mkdir ./cert
COPY ./server/cert/cert.pem ./cert/cert.pem
COPY ./server/cert/key.pem ./cert/key.pem

RUN go build -o server ./server/server.go

CMD ["/app/server/server"]
