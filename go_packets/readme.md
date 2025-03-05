```bash
go mod tidy
go run .
sudo apt-get install libpcap-dev
```

export PATH=/home/kej7be/go/bin:$PATH

sudo env PATH="/home/kej7be/go/bin:$PATH"

/usr/local/go/bin

sudo env PATH="/usr/local/go/bin:$PATH"


needed to add this to sudoer:

```bash
sudo visudo
```

Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin:/usr/local/go/bin"
Defaults env_keep += "http_proxy https_proxy GOPROXY"

# working on windows

because the vm was too slow, I need to try working directly on windows to see if this is any faster. the best I got on the vm was 96Mbps

set HTTP_PROXY=http://localhost:3128
set HTTPS_PROXY=http://localhost:3128
