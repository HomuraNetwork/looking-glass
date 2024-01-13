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
COPY index.html ./
RUN CGO_ENABLED=0 GOOS=linux go build -o /homuralg
EXPOSE 8080
CMD /homuralg -p 8080 -S .
