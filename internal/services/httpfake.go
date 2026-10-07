package services

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// Path-based fake APIs for HTTP honeypot ports that impersonate a specific
// product. The request is still captured by httpHandler exactly as for any
// other port; this only chooses the response.

// fakeResp is one canned response. Server, when set, replaces the nginx header.
type fakeResp struct {
	Status int
	Type   string
	Server string
	Header map[string]string
	Body   string
}

// httpFakes maps an HTTP port to its responder. ok=false falls through to the
// default nginx behaviour.
var httpFakes = map[string]func(r *http.Request) (fakeResp, bool){
	"9200": elasticFake,
	"2375": dockerFake,
}

func writeFake(w http.ResponseWriter, r *http.Request, f fakeResp) {
	h := w.Header()
	if f.Server != "" {
		h.Set("Server", f.Server)
	} else {
		h.Del("Server")
	}
	h.Set("Content-Type", f.Type)
	for k, v := range f.Header {
		h.Set(k, v)
	}
	if f.Status != http.StatusNoContent {
		h.Set("Content-Length", strconv.Itoa(len(f.Body)))
	}
	w.WriteHeader(f.Status)
	if r.Method != http.MethodHead {
		io.WriteString(w, f.Body)
	}
}

func jsonResp(status int, v string) fakeResp {
	return fakeResp{Status: status, Type: "application/json; charset=UTF-8", Body: v}
}

// ── Elasticsearch ─────────────────────────────────────────────────────────────

const esRoot = `{
  "name" : "node-1",
  "cluster_name" : "elasticsearch",
  "cluster_uuid" : "xQ2k9h_lRleh4TnOhK4LJw",
  "version" : {
    "number" : "7.17.16",
    "build_flavor" : "default",
    "build_type" : "deb",
    "build_hash" : "d252b2b3b7c2a9b9d2e3a0b0a0b3a9f5d2b0c1e7",
    "build_date" : "2024-01-10T10:02:15.000000000Z",
    "build_snapshot" : false,
    "lucene_version" : "8.11.1",
    "minimum_wire_compatibility_version" : "6.8.0",
    "minimum_index_compatibility_version" : "6.0.0-beta1"
  },
  "tagline" : "You Know, for Search"
}
`

const esIndicesJSON = `[{"health":"green","status":"open","index":".kibana_1","uuid":"k3Zr1QwVRaa0h1Zq0m0v3g","pri":"1","rep":"0","docs.count":"24","docs.deleted":"0","store.size":"89.1kb","pri.store.size":"89.1kb"},{"health":"yellow","status":"open","index":"logs-2024.03","uuid":"f8T2mXbQSbqk7bJrC1nQ0A","pri":"1","rep":"1","docs.count":"18452","docs.deleted":"0","store.size":"4.2mb","pri.store.size":"4.2mb"}]`

const esIndicesText = "health status index        uuid                   pri rep docs.count docs.deleted store.size pri.store.size\n" +
	"green  open   .kibana_1    k3Zr1QwVRaa0h1Zq0m0v3g   1   0         24            0     89.1kb         89.1kb\n" +
	"yellow open   logs-2024.03 f8T2mXbQSbqk7bJrC1nQ0A   1   1      18452            0      4.2mb          4.2mb\n"

func elasticFake(r *http.Request) (fakeResp, bool) {
	hdr := map[string]string{"X-elastic-product": "Elasticsearch"}
	with := func(f fakeResp) (fakeResp, bool) { f.Header = hdr; return f, true }
	path := strings.TrimRight(r.URL.Path, "/")
	switch {
	case path == "" && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		return with(jsonResp(200, esRoot))
	case path == "/_cat/indices":
		if r.URL.Query().Get("format") == "json" {
			return with(jsonResp(200, esIndicesJSON))
		}
		return with(fakeResp{Status: 200, Type: "text/plain; charset=UTF-8", Body: esIndicesText})
	case path == "/_cluster/health":
		return with(jsonResp(200, `{"cluster_name":"elasticsearch","status":"yellow","timed_out":false,"number_of_nodes":1,"number_of_data_nodes":1,"active_primary_shards":2,"active_shards":2,"relocating_shards":0,"initializing_shards":0,"unassigned_shards":1,"delayed_unassigned_shards":0,"number_of_pending_tasks":0,"number_of_in_flight_fetch":0,"task_max_waiting_in_queue_millis":0,"active_shards_percent_as_number":66.7}`))
	case path == "/_search" || strings.HasSuffix(path, "/_search"):
		return with(jsonResp(200, `{"took":1,"timed_out":false,"_shards":{"total":1,"successful":1,"skipped":0,"failed":0},"hits":{"total":{"value":0,"relation":"eq"},"max_score":null,"hits":[]}}`))
	}
	msg, _ := json.Marshal(fmt.Sprintf("no handler found for uri [%s] and method [%s]", truncate(r.URL.RequestURI(), 120), r.Method))
	return with(jsonResp(400, `{"error":`+string(msg)+`,"status":400}`))
}

// ── Docker Engine API ─────────────────────────────────────────────────────────

const dockerServer = "Docker/25.0.3 (linux)"

const dockerVersion = `{"Platform":{"Name":"Docker Engine - Community"},"Components":[{"Name":"Engine","Version":"25.0.3","Details":{"ApiVersion":"1.44","Arch":"amd64","BuildTime":"2024-02-06T21:12:00.000000000+00:00","Experimental":"false","GitCommit":"f417435","GoVersion":"go1.21.6","KernelVersion":"5.15.0-92-generic","MinAPIVersion":"1.24","Os":"linux"}}],"Version":"25.0.3","ApiVersion":"1.44","MinAPIVersion":"1.24","GitCommit":"f417435","GoVersion":"go1.21.6","Os":"linux","Arch":"amd64","KernelVersion":"5.15.0-92-generic","BuildTime":"2024-02-06T21:12:00.000000000+00:00"}
`

const dockerContainers = `[{"Id":"8dfafdbc3a40c4fb6c2c1a3b8d0b5f6d2f2f4c3b1a0e9d8c7b6a5f4e3d2c1b0a","Names":["/web"],"Image":"nginx:1.25","ImageID":"sha256:e784f4560448b14a66f55c26e1b4dad2c2877cc73d001b7cd0b18e24a700a070","Command":"/docker-entrypoint.sh nginx -g 'daemon off;'","Created":1709812800,"Ports":[{"IP":"0.0.0.0","PrivatePort":80,"PublicPort":8080,"Type":"tcp"}],"Labels":{},"State":"running","Status":"Up 3 days","HostConfig":{"NetworkMode":"default"},"Mounts":[]}]
`

func dockerFake(r *http.Request) (fakeResp, bool) {
	hdr := map[string]string{"Api-Version": "1.44", "Docker-Experimental": "false", "Ostype": "linux"}
	with := func(f fakeResp) (fakeResp, bool) { f.Server, f.Header = dockerServer, hdr; return f, true }
	// strip an optional /vX.YY/ prefix
	path := strings.TrimRight(r.URL.Path, "/")
	if strings.HasPrefix(path, "/v1.") {
		if _, rest, ok := strings.Cut(path[1:], "/"); ok {
			path = "/" + rest
		} else {
			path = ""
		}
	}
	switch {
	case path == "/_ping":
		return with(fakeResp{Status: 200, Type: "text/plain; charset=utf-8", Body: "OK"})
	case path == "/version":
		return with(jsonResp(200, dockerVersion))
	case path == "/containers/json":
		return with(jsonResp(200, dockerContainers))
	case path == "/images/json":
		return with(jsonResp(200, "[]\n"))
	case path == "/info":
		return with(jsonResp(200, `{"ID":"7TRN:IPZB:QYBB:VPBQ:UWHH:W5IU:G2UM:PEWB:QM7Q:PRLY:IKEH:OY6A","Containers":1,"ContainersRunning":1,"Images":3,"Driver":"overlay2","KernelVersion":"5.15.0-92-generic","OperatingSystem":"Ubuntu 22.04.3 LTS","OSType":"linux","Architecture":"x86_64","NCPU":4,"MemTotal":8341217280,"Name":"docker-host","ServerVersion":"25.0.3"}`+"\n"))
	case path == "/containers/create" && r.Method == http.MethodPost:
		return with(jsonResp(201, `{"Id":"`+randHex(32)+`","Warnings":[]}`+"\n"))
	case strings.HasPrefix(path, "/containers/") && strings.HasSuffix(path, "/start") && r.Method == http.MethodPost:
		return with(fakeResp{Status: 204, Type: "application/json"})
	}
	return with(jsonResp(404, `{"message":"page not found"}`+"\n"))
}
