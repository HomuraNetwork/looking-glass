FROM golang:1.19
RUN apt-get update && \
    apt-get --no-install-recommends -y install iputils-ping mtr traceroute && \
    rm -rf /var/lib/apt/lists/* && \
RUN curl https://nxtrace.org/nt |bash
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY intro.md ./
RUN CGO_ENABLED=0 GOOS=linux go build -o /homuralg
EXPOSE 8000
CMD ["/homuralg"]
