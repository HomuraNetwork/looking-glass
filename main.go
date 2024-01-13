package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

var (
	mainDomain string
	page       string
	port       string
	ip         string
	key        string
	ipv4Addr   string
	ipv4URL    string
	ipv6Addr   string
	ipv6URL    string
)

var allowedFileTypes = map[string]bool{
	".html": true,
	".htm":  true,
	".css":  true,
	".js":   true,
	".svg":  true,
	".png":  true,
	".json": true,
	".yaml": true,
	".yml":  true,
	".txt":  true,
	".md":   true,
	".ico":  true,
}

func isIPorDomain(target string) bool {

	if net.ParseIP(target) != nil {
		return true
	}

	if len(target) > 255 || len(target) < 1 {
		return false
	}
	if strings.HasSuffix(target, ".") {
		target = target[:len(target)-1]
	}
	return regexp.MustCompile(`^[a-zA-Z0-9-\.]+$`).MatchString(target) && !strings.Contains(target, "..")
}

func main() {
	var port string
	flag.StringVar(&port, "p", "8000", "Port to listen on")
	flag.StringVar(&port, "port", "8000", "Port to listen on (shorthand)")
	flag.StringVar(&mainDomain, "domain", "", "Main domain for CORS (leave empty to disable CORS)")
	flag.StringVar(&mainDomain, "D", "", "Main domain for CORS (leave empty to disable CORS)(shorthand)")
	flag.StringVar(&page, "S", "", "Path to a static HTML page to be served")
	flag.StringVar(&page, "static", "", "Path to a static HTML page to be served (shorthand)")
	flag.StringVar(&ip, "ip", "0.0.0.0", "IP address to listen on")
	flag.StringVar(&key, "K", "", "Key for generating file hash")
	flag.StringVar(&key, "key", "", "Key for generating file hash (shorthand)")
	flag.StringVar(&ipv4Addr, "ipv4-addr", "", "IPv4 address of the server")
	flag.StringVar(&ipv4URL, "ipv4-url", "", "URL for IPv4 address of the server")
	flag.StringVar(&ipv6Addr, "ipv6-addr", "", "IPv6 address of the server")
	flag.StringVar(&ipv6URL, "ipv6-url", "", "URL for IPv6 address of the server")

	help := flag.Bool("h", false, "Display help")
	helpShorthand := flag.Bool("help", false, "Display help (shorthand)")

	flag.Parse()
	if *help || *helpShorthand {
		fmt.Println("Usage of program:")
		flag.PrintDefaults()
		return
	}

	fmt.Printf("Server is starting at %s:%s\n", ip, port)
	if page != "" {
		fs := http.FileServer(http.Dir(page))

		http.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			if isAllowedFileType(r.URL.Path) {
				fs.ServeHTTP(w, r)
			} else {
				http.Error(w, "Forbidden", http.StatusForbidden)
			}
		}))
		fmt.Printf("Static Page is serving at %s\n", page)
		fmt.Printf("Only files with the following extensions are allowed: %v\n", getKeys(allowedFileTypes))
	}
	http.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		if mainDomain != "" {
			setupCors(&w, r)
		}
		fmt.Fprintf(w, "User-agent: *\nDisallow: /\n")
	})
	http.HandleFunc("/info", handleInfo)
	http.HandleFunc("/intro", handleIntro)
	http.HandleFunc("/download/", handleFileDownload)
	http.HandleFunc("/lg_backend", looking_glass)
	http.HandleFunc("/generate_204", func(w http.ResponseWriter, r *http.Request) {
		if mainDomain != "" {
			setupCors(&w, r)
		}
		generate204(w, r)
	})

	log.Fatal(http.ListenAndServe(ip+":"+port, nil))
}

func getClientIP(r *http.Request) string {

	xForwardedFor := r.Header.Get("X-Forwarded-For")
	if xForwardedFor != "" {
		ips := strings.Split(xForwardedFor, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	xRealIP := r.Header.Get("X-Real-IP")
	if xRealIP != "" {
		return xRealIP
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func handleIntro(w http.ResponseWriter, r *http.Request) {
	introFile := "intro.md"

	// Check if the intro.md file exists
	if _, err := os.Stat(introFile); os.IsNotExist(err) {
		// If the file doesn't exist, return a default message
		defaultMessage := "A simple looking glass powered by [Homura Network Limited](https://homura.network), create an intro.md to change this"
		fmt.Fprint(w, defaultMessage)
		return
	}

	// Read the content of the intro.md file
	content, err := ioutil.ReadFile(introFile)
	if err != nil {
		http.Error(w, "Error reading intro.md file", http.StatusInternalServerError)
		return
	}

	// Set the Content-Type header to indicate markdown content
	w.Header().Set("Content-Type", "text/markdown")

	// Write the content of intro.md to the response
	w.Write(content)
}

func handleInfo(w http.ResponseWriter, r *http.Request) {
	link100M, link1000M := generateDownloadLinks(r)

	visitorIP := getClientIP(r)

	if ipv4Addr == "" {
		ipv4Addr = getPublicIPv4()
	}

	if ipv6Addr == "" {
		ipv6Addr = getPublicIPv6()
	}

	info := map[string]string{
		"100M":      link100M,
		"1000M":     link1000M,
		"VisitorIP": visitorIP,
	}

	if ipv4Addr != "" {
		info["IPv4Addr"] = ipv4Addr
		if ipv4URL != "" {
			info["IPv4URL"] = ipv4URL
		} else {
			info["IPv4URL"] = "http://" + ipv4Addr
		}
	}

	if ipv6Addr != "" {
		info["IPv6Addr"] = ipv6Addr
		if ipv6URL != "" {
			info["IPv6URL"] = ipv6URL
		} else {
			info["IPv6URL"] = "http://[" + ipv6Addr + "]"
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

func getPublicIPv4() string {
	return getPublicIP("https://1.1.1.1/cdn-cgi/trace")
}

func getPublicIPv6() string {
	return getPublicIP("https://[2606:4700:4700::1111]/cdn-cgi/trace")
}

func getPublicIP(url string) string {
	resp, err := http.Get(url)
	if err != nil {
		log.Printf("Failed to get public IP: %v", err)
		return ""
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "ip=") {
			return strings.TrimPrefix(line, "ip=")
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error reading response: %v", err)
	}

	return ""
}

func generateHash(ip string) string {
	today := time.Now().Format("2006-01-02")
	sha1Hash := sha1.Sum([]byte(ip + key + today))
	md5Hash := md5.Sum(sha1Hash[:])
	return hex.EncodeToString(md5Hash[:])
}

func generateDownloadLinks(r *http.Request) (string, string) {
	ip := getClientIP(r)
	hash := generateHash(ip)

	link100M := "/download/" + hash + "/100M"
	link1000M := "/download/" + hash + "/1000M"

	return link100M, link1000M
}

func handleFileDownload(w http.ResponseWriter, r *http.Request) {
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 4 {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	hash := pathParts[2]
	fileSizePart := pathParts[3]

	expectedHash := generateHash(getClientIP(r))
	if hash != expectedHash {
		http.Error(w, "Invalid or expired link", http.StatusForbidden)
		return
	}

	var fileSize int64
	if fileSizePart == "100M" {
		fileSize = 100 * 1024 * 1024
	} else if fileSizePart == "1000M" {
		fileSize = 1000 * 1024 * 1024
	} else {
		http.Error(w, "Invalid file size", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename="+hash+"_"+fileSizePart+".bin")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(fileSize, 10))
	sendVirtualFile(w, fileSize)
}
func sendVirtualFile(w http.ResponseWriter, fileSize int64) {

	dataBlock := []byte("0123456789ABCDEF")

	for i := int64(0); i < fileSize; i += int64(len(dataBlock)) {
		_, err := w.Write(dataBlock)
		if err != nil {

			fmt.Println("Error writing to response:", err)
			break
		}
	}
}

func isAllowedFileType(path string) bool {
	if path == "/" || strings.HasSuffix(path, "/") {
		return true
	}

	ext := strings.ToLower(filepath.Ext(path))
	_, allowed := allowedFileTypes[ext]
	return allowed
}

func getKeys(m map[string]bool) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func setupCors(w *http.ResponseWriter, req *http.Request) {
	(*w).Header().Set("Access-Control-Allow-Origin", getOrigin(req))
	fmt.Printf("CORS is enabled for %s\n", getOrigin(req))
}

func getOrigin(req *http.Request) string {
	origin := req.Header.Get("Origin")
	if origin == "" || mainDomain == "" {
		return "*"
	}

	if strings.HasSuffix(origin, mainDomain) {
		return origin
	}
	return "*"
}

func generate204(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

type Command struct {
	Type   string `json:"type"`
	IPVer  string `json:"ipver"`
	Target string `json:"target"`
	Count  int    `json:"count"`
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func looking_glass(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Print("upgrade:", err)
		return
	}
	defer conn.Close()

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Println("read:", err)
			break
		}

		var cmd Command
		if err := json.Unmarshal(message, &cmd); err != nil {
			log.Println("json.Unmarshal failed:", err)
			continue
		}

		go handleCommand(conn, cmd)
	}
}

func handleCommand(conn *websocket.Conn, cmd Command) {
	if !isIPorDomain(cmd.Target) {
		sendErrorMessage(conn, "Invalid target: must be an IP address or domain name")
		return
	}
	switch cmd.Type {
	case "ping":
		executePing(conn, cmd)
	case "mtr":
		executeMtr(conn, cmd)
	case "traceroute":
		executeTraceroute(conn, cmd)
	case "nexttrace":
		executeNexttrace(conn, cmd)
	}
}

func executePing(conn *websocket.Conn, cmd Command) {
	count := cmd.Count
	if count <= 0 || count > 20 {
		count = 4
	}
	args := []string{"-O", "-c", strconv.Itoa(count), "-w", "15", cmd.Target}
	if cmd.IPVer == "ipv6" {
		args = append([]string{"-6"}, args...)
	} else {
		args = append([]string{"-4"}, args...)
	}
	sendInitialMessage(conn, "Please wait...")

	execCmd := exec.Command("ping", args...)
	runAndSendOutput(execCmd, conn)
}

func executeMtr(conn *websocket.Conn, cmd Command) {
	count := cmd.Count
	if count <= 0 || count > 20 {
		count = 5
	}
	args := []string{"--report", "-c", strconv.Itoa(count), cmd.Target}
	if cmd.IPVer == "ipv6" {
		args = append([]string{"-6"}, args...)
	} else {
		args = append([]string{"-4"}, args...)
	}

	sendInitialMessage(conn, "MTR may need 30s to 1m to finish, please wait...")

	execCmd := exec.Command("mtr", args...)
	runAndSendOutput(execCmd, conn)
}

func executeTraceroute(conn *websocket.Conn, cmd Command) {
	args := []string{"-w", "2", cmd.Target}
	if cmd.IPVer == "ipv6" {
		args = append([]string{"-6"}, args...)
	} else {
		args = append([]string{"-4"}, args...)
	}
	sendInitialMessage(conn, "Please wait...")

	execCmd := exec.Command("traceroute", args...)
	runAndSendOutput(execCmd, conn)
}

func executeNexttrace(conn *websocket.Conn, cmd Command) {
	args := []string{"-C", "--map", "-g", "en", cmd.Target}
	if cmd.IPVer == "ipv6" {
		args = append([]string{"--ipv6"}, args...)
	} else {
		args = append([]string{"--ipv4"}, args...)
	}
	sendInitialMessage(conn, "NextTrace - An open source light-weight visual traceroute tool implemented by Golang.")
	sendInitialMessage(conn, "Please wait...")

	execCmd := exec.Command("nexttrace", args...)
	runAndSendOutput(execCmd, conn)
}

func sendInitialMessage(conn *websocket.Conn, message string) {
	conn.WriteMessage(websocket.TextMessage, []byte(message))
}

func runAndSendOutput(cmd *exec.Cmd, conn *websocket.Conn) {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		sendErrorMessage(conn, "Error creating stdout pipe: "+err.Error())
		return
	}

	if err := cmd.Start(); err != nil {
		sendErrorMessage(conn, "Error starting command: "+err.Error())
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		conn.WriteMessage(websocket.TextMessage, []byte(line))
	}

	if err := cmd.Wait(); err != nil {
		sendErrorMessage(conn, "Error waiting for command completion: "+err.Error())
	}
}

func sendErrorMessage(conn *websocket.Conn, message string) {
	conn.WriteMessage(websocket.TextMessage, []byte("Error: "+message))
}
